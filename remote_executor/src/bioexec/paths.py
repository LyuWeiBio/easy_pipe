"""Descriptor-anchored confinement for configured remote path roles."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import secrets
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePath

from .config import ConfiguredRoot
from .errors import AgentFailure, ReturnCode

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class AuthorizedPath:
    """A normalized request path tied to one configured root."""

    path: Path
    root: ConfiguredRoot
    relative_parts: tuple[str, ...]


class PathGuard:
    """Open request paths through no-follow directory descriptors."""

    def authorize(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        allow_root: bool = False,
    ) -> AuthorizedPath:
        requested = _request_path(value)
        matches: list[tuple[int, ConfiguredRoot, tuple[str, ...]]] = []
        for root in roots:
            try:
                relative = requested.relative_to(root.path)
            except ValueError:
                continue
            parts = () if relative == Path(".") else relative.parts
            matches.append((len(root.path.parts), root, parts))
        if not matches:
            raise AgentFailure(
                ReturnCode.PATH_OUTSIDE_ALLOWLIST,
                "PATH_OUTSIDE_ALLOWLIST",
                "requested path is outside its configured role roots",
            )
        _length, root, parts = max(matches, key=lambda item: item[0])
        if not parts and not allow_root:
            raise AgentFailure(
                ReturnCode.PATH_OUTSIDE_ALLOWLIST,
                "ROLE_ROOT_TARGET_FORBIDDEN",
                "an operation cannot use the role root itself as its target",
            )
        return AuthorizedPath(root.path.joinpath(*parts), root, tuple(parts))

    @contextlib.contextmanager
    def open_directory(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        allow_root: bool = False,
        require_trusted_owner: bool = False,
        require_no_group_world_write: bool = False,
        require_private: bool = False,
    ) -> Iterator[tuple[int, AuthorizedPath]]:
        authorized = self.authorize(value, roots, allow_root=allow_root)
        descriptor = self._open_root(
            authorized.root,
            require_trusted_owner=require_trusted_owner,
            require_no_group_world_write=require_no_group_world_write,
            require_private=require_private,
        )
        try:
            walking_descriptor = descriptor
            descriptor = -1
            descriptor = self._walk_directories(
                walking_descriptor,
                authorized.relative_parts,
                require_trusted_owner=require_trusted_owner,
                require_no_group_world_write=require_no_group_world_write,
                require_private=require_private,
            )
            yield descriptor, authorized
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @contextlib.contextmanager
    def open_parent(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        require_trusted_owner: bool = False,
        require_no_group_world_write: bool = False,
        require_private: bool = False,
    ) -> Iterator[tuple[int, str, AuthorizedPath]]:
        authorized = self.authorize(value, roots)
        parent_parts = authorized.relative_parts[:-1]
        leaf = authorized.relative_parts[-1]
        descriptor = self._open_root(
            authorized.root,
            require_trusted_owner=require_trusted_owner,
            require_no_group_world_write=require_no_group_world_write,
            require_private=require_private,
        )
        try:
            walking_descriptor = descriptor
            descriptor = -1
            descriptor = self._walk_directories(
                walking_descriptor,
                parent_parts,
                require_trusted_owner=require_trusted_owner,
                require_no_group_world_write=require_no_group_world_write,
                require_private=require_private,
            )
            yield descriptor, leaf, authorized
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @contextlib.contextmanager
    def open_regular(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        require_trusted_owner: bool = False,
        require_no_group_world_write: bool = False,
    ) -> Iterator[tuple[int, AuthorizedPath, os.stat_result]]:
        with self.open_parent(
            value,
            roots,
            require_trusted_owner=require_trusted_owner,
            require_no_group_world_write=require_no_group_world_write,
        ) as (parent, leaf, authorized):
            try:
                descriptor = os.open(leaf, _FILE_FLAGS, dir_fd=parent)
            except OSError as exc:
                raise _access_failure(exc) from exc
            try:
                metadata = os.fstat(descriptor)
                current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(current.st_mode)
                    or not _same_inode(metadata, current)
                ):
                    raise AgentFailure(
                        ReturnCode.SYMLINK_OR_ESCAPE,
                        "UNSAFE_REGULAR_FILE",
                        "requested input is not a stable regular file",
                    )
                _require_permissions(
                    metadata,
                    require_trusted_owner=require_trusted_owner,
                    require_no_group_world_write=require_no_group_world_write,
                    require_private=False,
                )
                yield descriptor, authorized, metadata
            finally:
                os.close(descriptor)

    def require_absent(self, value: str, roots: tuple[ConfiguredRoot, ...]) -> AuthorizedPath:
        with self.open_parent(value, roots) as (parent, leaf, authorized):
            try:
                os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return authorized
            raise AgentFailure(
                ReturnCode.STATE_CONFLICT,
                "TARGET_ALREADY_EXISTS",
                "a create-only execution target already exists",
            )

    def create_directory_exclusive(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        mode: int = 0o700,
    ) -> tuple[AuthorizedPath, dict[str, int]]:
        with self.open_parent(
            value,
            roots,
            require_trusted_owner=True,
            require_no_group_world_write=True,
        ) as (parent, leaf, authorized):
            try:
                os.mkdir(leaf, mode=mode, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "TARGET_ALREADY_EXISTS",
                    "a create-only execution target already exists",
                ) from exc
            except OSError as exc:
                raise _access_failure(exc) from exc
            descriptor = os.open(leaf, _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                metadata = os.fstat(descriptor)
                current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(current.st_mode)
                    or not _same_inode(metadata, current)
                ):
                    raise AgentFailure(
                        ReturnCode.SYMLINK_OR_ESCAPE,
                        "PATH_BINDING_CHANGED",
                        "execution target changed while it was being created",
                    )
                _require_permissions(
                    metadata,
                    require_trusted_owner=True,
                    require_no_group_world_write=True,
                    require_private=True,
                )
                return authorized, _directory_identity(metadata)
            finally:
                os.close(descriptor)

    def test_writable_parent(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        target_must_be_absent: bool,
        target_private: bool = False,
    ) -> tuple[AuthorizedPath, int, dict[str, int] | None]:
        """Probe the target parent using an exclusive sentinel and return free bytes."""

        with self.open_parent(
            value,
            roots,
            require_trusted_owner=True,
            require_no_group_world_write=True,
        ) as (parent, leaf, authorized):
            try:
                metadata = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                metadata = None
            if target_must_be_absent and metadata is not None:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "TARGET_ALREADY_EXISTS",
                    "a create-only execution target already exists",
                )
            if metadata is not None and (
                stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise AgentFailure(
                    ReturnCode.SYMLINK_OR_ESCAPE,
                    "UNSAFE_DIRECTORY_TARGET",
                    "execution target is not a safe directory",
                )
            probe_directory = parent
            owned_probe_directory = -1
            if metadata is not None:
                try:
                    owned_probe_directory = os.open(leaf, _DIRECTORY_FLAGS, dir_fd=parent)
                except OSError as exc:
                    raise _access_failure(exc) from exc
                opened = os.fstat(owned_probe_directory)
                if not _same_inode(metadata, opened):
                    os.close(owned_probe_directory)
                    raise AgentFailure(
                        ReturnCode.SYMLINK_OR_ESCAPE,
                        "PATH_BINDING_CHANGED",
                        "execution target changed while it was being checked",
                    )
                _require_permissions(
                    opened,
                    require_trusted_owner=True,
                    require_no_group_world_write=True,
                    require_private=target_private,
                )
                probe_directory = owned_probe_directory
            sentinel = f".bioexec-write-probe-{secrets.token_hex(12)}"
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = -1
            free_bytes = 0
            try:
                descriptor = os.open(sentinel, flags, 0o600, dir_fd=probe_directory)
                os.write(descriptor, b"bioexec-preflight\n")
                os.fsync(descriptor)
                filesystem = os.fstatvfs(probe_directory)
                free_bytes = filesystem.f_bavail * filesystem.f_frsize
            except OSError as exc:
                raise _access_failure(exc) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(sentinel, dir_fd=probe_directory)
                if owned_probe_directory >= 0:
                    os.close(owned_probe_directory)
            identity = None if metadata is None else _directory_identity(metadata)
            return authorized, free_bytes, identity

    def sha256_regular(
        self,
        value: str,
        roots: tuple[ConfiguredRoot, ...],
        *,
        maximum_bytes: int,
    ) -> tuple[str, int]:
        with self.open_regular(value, roots) as (descriptor, _authorized, metadata):
            if metadata.st_size > maximum_bytes:
                raise AgentFailure(
                    ReturnCode.BUDGET_EXCEEDED,
                    "FILE_BUDGET_EXCEEDED",
                    "file exceeds its configured size limit",
                )
            digest = hashlib.sha256()
            remaining = maximum_bytes + 1
            total = 0
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
                remaining -= len(chunk)
            if total > maximum_bytes:
                raise AgentFailure(
                    ReturnCode.BUDGET_EXCEEDED,
                    "FILE_BUDGET_EXCEEDED",
                    "file exceeds its configured size limit",
                )
            return digest.hexdigest(), total

    @staticmethod
    def _walk_directories(
        descriptor: int,
        parts: tuple[str, ...],
        *,
        require_trusted_owner: bool,
        require_no_group_world_write: bool,
        require_private: bool,
    ) -> int:
        current = descriptor
        try:
            for part in parts:
                next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
                try:
                    metadata = os.fstat(next_descriptor)
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise NotADirectoryError(part)
                    _require_permissions(
                        metadata,
                        require_trusted_owner=require_trusted_owner,
                        require_no_group_world_write=require_no_group_world_write,
                        require_private=require_private,
                    )
                except BaseException:
                    os.close(next_descriptor)
                    raise
                os.close(current)
                current = next_descriptor
            return current
        except OSError as exc:
            os.close(current)
            raise _access_failure(exc) from exc
        except BaseException:
            os.close(current)
            raise

    @staticmethod
    def _open_root(
        root: ConfiguredRoot,
        *,
        require_trusted_owner: bool,
        require_no_group_world_write: bool,
        require_private: bool,
    ) -> int:
        try:
            descriptor = os.open(root.path, _DIRECTORY_FLAGS)
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise _access_failure(exc) from exc
        if (metadata.st_dev, metadata.st_ino) != (root.device, root.inode):
            os.close(descriptor)
            raise AgentFailure(
                ReturnCode.SYMLINK_OR_ESCAPE,
                "CONFIGURED_ROOT_CHANGED",
                "a configured path root changed after agent startup",
            )
        try:
            _require_permissions(
                metadata,
                require_trusted_owner=require_trusted_owner,
                require_no_group_world_write=require_no_group_world_write,
                require_private=require_private,
            )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor


def safe_relative_path(value: str) -> tuple[str, ...]:
    if (
        not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(value.encode("utf-8")) > 4096
    ):
        raise AgentFailure(ReturnCode.PROTOCOL_ERROR, "UNSAFE_RELATIVE_PATH", "unsafe path")
    path = PurePath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise AgentFailure(
            ReturnCode.PROTOCOL_ERROR,
            "UNSAFE_RELATIVE_PATH",
            "deployment paths must be normalized relative paths",
        )
    return path.parts


def _request_path(value: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(value.encode("utf-8")) > 4096
    ):
        raise AgentFailure(ReturnCode.PROTOCOL_ERROR, "UNSAFE_PATH", "path text is unsafe")
    pure = PurePath(value)
    if not pure.is_absolute() or ".." in pure.parts:
        raise AgentFailure(ReturnCode.PROTOCOL_ERROR, "UNSAFE_PATH", "path must be absolute")
    return Path(os.path.normpath(value))


def _access_failure(error: OSError) -> AgentFailure:
    if error.errno in {errno.ELOOP}:
        return AgentFailure(
            ReturnCode.SYMLINK_OR_ESCAPE,
            "SYMLINK_FORBIDDEN",
            "path traversal encountered a symlink",
        )
    return AgentFailure(
        ReturnCode.PATH_UNAVAILABLE,
        "PATH_UNAVAILABLE",
        "a configured execution path is unavailable",
        context={} if error.errno is None else {"errno": error.errno},
    )


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _require_permissions(
    metadata: os.stat_result,
    *,
    require_trusted_owner: bool,
    require_no_group_world_write: bool,
    require_private: bool,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        (require_trusted_owner and metadata.st_uid not in {0, os.geteuid()})
        or (require_no_group_world_write and mode & 0o022)
        or (require_private and mode & 0o077)
    ):
        raise AgentFailure(
            ReturnCode.SYMLINK_OR_ESCAPE,
            "UNTRUSTED_PATH_PERMISSIONS",
            "path ownership or permissions violate the configured trust boundary",
        )


def _directory_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "owner": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


__all__ = ["AuthorizedPath", "PathGuard", "safe_relative_path"]
