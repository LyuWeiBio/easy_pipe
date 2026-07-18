"""Overwrite and path-security tests for source profile storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from biopipe.models import SourceProfile
from biopipe.sources import SourceRegistry, SourceRegistryError, SourceRegistryErrorCode


def _profile(alias: str = "original-host") -> SourceProfile:
    return SourceProfile(
        source_id="source-a",
        ssh_alias=alias,
        allowed_roots=["/srv/synthetic-raw"],
    )


def _code(error: SourceRegistryError) -> str:
    return error.code.value if hasattr(error.code, "value") else str(error.code)


def test_duplicate_add_cannot_overwrite_existing_source(tmp_path: Path) -> None:
    registry = SourceRegistry(tmp_path / "sources")
    original = _profile()
    registry.add(original)

    with pytest.raises(SourceRegistryError) as exc_info:
        registry.add(_profile(alias="replacement-host"))

    assert _code(exc_info.value) == SourceRegistryErrorCode.SOURCE_ALREADY_EXISTS.value
    assert registry.get("source-a") == original
    assert {path.name for path in registry.directory.iterdir()} == {"source-a.json"}


@pytest.mark.parametrize(
    "source_id",
    ["../outside", "../../etc/passwd", "/absolute", "source-a/child", "--option"],
)
def test_registry_identifier_cannot_escape_storage_directory(
    tmp_path: Path,
    source_id: str,
) -> None:
    registry = SourceRegistry(tmp_path / "sources")

    with pytest.raises(SourceRegistryError) as exc_info:
        registry.get(source_id)

    assert _code(exc_info.value) == SourceRegistryErrorCode.SOURCE_NOT_FOUND.value
    assert not registry.directory.exists()


def test_registry_refuses_symlinked_profile_file(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(_profile().model_dump_json(), encoding="utf-8")
    (directory / "source-a.json").symlink_to(outside)
    registry = SourceRegistry(directory)

    with pytest.raises(SourceRegistryError) as exc_info:
        registry.get("source-a")

    assert _code(exc_info.value) == SourceRegistryErrorCode.SOURCE_STORAGE_FAILED.value


def test_registry_refuses_symlinked_registry_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside-sources"
    outside.mkdir()
    linked_directory = tmp_path / "sources"
    linked_directory.symlink_to(outside, target_is_directory=True)
    registry = SourceRegistry(linked_directory)

    with pytest.raises(SourceRegistryError) as exc_info:
        registry.add(_profile())

    assert _code(exc_info.value) == SourceRegistryErrorCode.SOURCE_STORAGE_FAILED.value
    assert list(outside.iterdir()) == []


def test_registry_rejects_oversized_profile_without_loading_it(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    (directory / "source-a.json").write_bytes(b" " * (1024 * 1024 + 1))
    registry = SourceRegistry(directory)

    with pytest.raises(SourceRegistryError) as exc_info:
        registry.get("source-a")

    assert _code(exc_info.value) == SourceRegistryErrorCode.SOURCE_STORAGE_FAILED.value
