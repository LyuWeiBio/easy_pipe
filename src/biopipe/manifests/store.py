"""Create-only local storage for manifest lifecycle artifacts."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Final, TypeVar

from pydantic import BaseModel, ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import DatasetManifest, ManifestOverrides

_SAFE_NAME: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
_MAX_ARTIFACT_BYTES: Final[int] = 16 * 1024 * 1024
ModelT = TypeVar("ModelT", bound=BaseModel)


class ManifestArtifactStore:
    """Persist artifacts without silently replacing an earlier scan or decision."""

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory).expanduser()

    @property
    def directory(self) -> Path:
        return self._directory

    def create_model(self, name: str, model: BaseModel) -> Path:
        """Create one deterministic JSON model artifact if the name is unused."""

        return self.create_bundle({name: model})[name]

    def create_text(self, name: str, value: str) -> Path:
        """Create one UTF-8 artifact with fsync and create-if-absent semantics."""

        return self.create_bundle({name: value})[name]

    def create_bundle(self, artifacts: Mapping[str, BaseModel | str]) -> dict[str, Path]:
        """Create a complete artifact bundle or leave every destination untouched.

        All names, payloads, and destinations are checked before the first artifact is
        linked into place. The links retain create-if-absent semantics, and any links
        made before a later race or I/O failure are removed only when they still refer
        to this operation's staged inode.
        """

        if not artifacts:
            return {}

        rendered: list[tuple[str, Path, bytes]] = []
        for name, value in artifacts.items():
            destination = self._artifact_path(name)
            raw = self._encode_artifact(value)
            if len(raw) > _MAX_ARTIFACT_BYTES:
                raise self._error("write", name, errno.EFBIG)
            rendered.append((name, destination, raw))

        staged: list[tuple[str, Path, Path]] = []
        linked: list[tuple[Path, Path]] = []
        active_name: str | None = None
        try:
            self._ensure_directory()
            for name, destination, _raw in rendered:
                try:
                    destination.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise self._error("preflight", name, exc.errno) from exc
                raise self._error("create", name, errno.EEXIST)

            for name, destination, raw in rendered:
                active_name = name
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=self._directory,
                    prefix=".biopipe-bundle-",
                    suffix=".tmp",
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    staged.append((name, destination, temporary_path))
                    temporary.write(raw)
                    temporary.flush()
                    os.fsync(temporary.fileno())

            for name, destination, temporary_path in staged:
                active_name = name
                os.link(temporary_path, destination)
                linked.append((destination, temporary_path))
            self._fsync_directory()
            return {name: destination for name, destination, _temporary in staged}
        except FileExistsError as exc:
            self._rollback_links(linked)
            raise self._error("create", active_name, exc.errno) from exc
        except BioPipeError:
            self._rollback_links(linked)
            raise
        except OSError as exc:
            self._rollback_links(linked)
            raise self._error("write", active_name, exc.errno) from exc
        finally:
            for _name, _destination, temporary_path in staged:
                with suppress(OSError):
                    temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _encode_artifact(value: BaseModel | str) -> bytes:
        if isinstance(value, BaseModel):
            text = (
                json.dumps(
                    value.model_dump(mode="json", exclude_none=False),
                    allow_nan=False,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
        else:
            text = value
        return text.encode("utf-8")

    def _rollback_links(self, linked: list[tuple[Path, Path]]) -> None:
        if not linked:
            return
        for destination, temporary_path in reversed(linked):
            try:
                if os.path.samestat(destination.lstat(), temporary_path.lstat()):
                    destination.unlink()
            except FileNotFoundError:
                continue
        self._fsync_directory()

    def read_manifest(self, name: str) -> DatasetManifest:
        return self._read_model(name, DatasetManifest)

    def read_overrides(self, name: str) -> ManifestOverrides:
        return self._read_model(name, ManifestOverrides)

    def _read_model(self, name: str, model_type: type[ModelT]) -> ModelT:
        path = self._artifact_path(name)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > _MAX_ARTIFACT_BYTES:
                raise OSError(errno.EINVAL, "invalid manifest artifact")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = None
                raw = stream.read(_MAX_ARTIFACT_BYTES + 1)
            if len(raw) > _MAX_ARTIFACT_BYTES:
                raise OSError(errno.EFBIG, "manifest artifact is too large")
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            return model_type.model_validate(data)
        except (OSError, UnicodeError, ValueError, TypeError, ValidationError) as exc:
            error_number = exc.errno if isinstance(exc, OSError) else None
            raise self._error("read", name, error_number) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _ensure_directory(self) -> None:
        try:
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not stat.S_ISDIR(self._directory.lstat().st_mode):
                raise NotADirectoryError(errno.ENOTDIR, "manifest store is not a directory")
        except OSError as exc:
            raise self._error("initialize", None, exc.errno) from exc

    def _fsync_directory(self) -> None:
        descriptor = os.open(
            self._directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _artifact_path(self, name: str) -> Path:
        if not _SAFE_NAME.fullmatch(name):
            raise self._error("validate", "<invalid>", None)
        return self._directory / name

    @staticmethod
    def _error(operation: str, name: str | None, error_number: int | None) -> BioPipeError:
        context: dict[str, str | int] = {"operation": operation}
        if name is not None:
            context["artifact"] = name
        if error_number is not None:
            context["errno"] = error_number
        return BioPipeError(
            ErrorCode.MANIFEST_STORAGE_FAILED,
            "The manifest artifact store could not complete the operation.",
            context=context,
            remediation=["Check the artifact name, directory permissions, and existing files."],
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


__all__ = ["ManifestArtifactStore"]
