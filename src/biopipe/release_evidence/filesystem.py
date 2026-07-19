"""Descriptor-level filesystem checks for private release evidence."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from contextlib import suppress
from typing import Final, TypeAlias

FileIdentity: TypeAlias = tuple[int, int]

_ACL_TYPE_EXTENDED: Final[int] = 0x00000100
_MAX_ANCESTRY_DEPTH: Final[int] = 1024
_LINUX_ACL_XATTRS: Final[tuple[str, ...]] = (
    "system.posix_acl_access",
    "system.posix_acl_default",
    "system.richacl",
    "system.nfs4_acl",
)


def descriptor_identity(descriptor: int) -> FileIdentity:
    """Return the stable device/inode identity for one open descriptor."""

    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def descriptor_has_extended_acl(descriptor: int) -> bool:
    """Detect a non-mode ACL on a descriptor without pathname re-resolution."""

    if not isinstance(descriptor, int) or isinstance(descriptor, bool) or descriptor < 0:
        raise OSError(errno.EBADF, "invalid descriptor")
    if sys.platform == "darwin":
        return _darwin_descriptor_has_extended_acl(descriptor)
    if sys.platform.startswith("linux"):
        names = frozenset(os.listxattr(descriptor))
        return not names.isdisjoint(_LINUX_ACL_XATTRS)
    raise OSError(errno.ENOTSUP, "descriptor ACL inspection is unavailable")


def require_no_extended_acl(descriptor: int) -> None:
    """Reject any extended ACL on an already-open filesystem object."""

    if descriptor_has_extended_acl(descriptor):
        raise OSError(errno.EACCES, "extended ACL is not allowed for private evidence")


def require_directory_outside_identities(
    descriptor: int,
    forbidden_identities: frozenset[FileIdentity],
) -> None:
    """Require an open directory and its current ancestors to avoid fixed identities."""

    if not forbidden_identities:
        return
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.dup(descriptor)
    try:
        for _depth in range(_MAX_ANCESTRY_DEPTH):
            metadata = os.fstat(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError(errno.ENOTDIR, "ancestry descriptor is not a directory")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in forbidden_identities:
                raise OSError(errno.EACCES, "directory enters a protected root")
            parent = os.open("..", flags, dir_fd=current)
            parent_identity = descriptor_identity(parent)
            if parent_identity == identity:
                os.close(parent)
                return
            os.close(current)
            current = parent
        raise OSError(errno.ELOOP, "directory ancestry exceeds its safety bound")
    finally:
        with suppress(OSError):
            os.close(current)


def _darwin_descriptor_has_extended_acl(descriptor: int) -> bool:
    library = ctypes.CDLL(None, use_errno=True)
    get_acl = getattr(library, "acl_get_fd_np", None)
    free_acl = getattr(library, "acl_free", None)
    if get_acl is None or free_acl is None:
        raise OSError(errno.ENOTSUP, "macOS ACL inspection is unavailable")
    get_acl.argtypes = (ctypes.c_int, ctypes.c_int)
    get_acl.restype = ctypes.c_void_p
    free_acl.argtypes = (ctypes.c_void_p,)
    free_acl.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl_pointer = get_acl(descriptor, _ACL_TYPE_EXTENDED)
    if acl_pointer:
        ctypes.set_errno(0)
        if free_acl(acl_pointer) != 0:
            error_number = ctypes.get_errno() or errno.EIO
            raise OSError(error_number, os.strerror(error_number))
        return True
    error_number = ctypes.get_errno()
    if error_number in {0, errno.ENOENT}:
        return False
    raise OSError(error_number, os.strerror(error_number))


__all__ = [
    "FileIdentity",
    "descriptor_has_extended_acl",
    "descriptor_identity",
    "require_directory_outside_identities",
    "require_no_extended_acl",
]
