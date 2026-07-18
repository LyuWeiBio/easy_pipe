"""Integration tests for the local file-backed source registry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from biopipe.models import SourceProfile
from biopipe.sources import SourceRegistry, SourceRegistryError, SourceRegistryErrorCode


def _profile(source_id: str, root: str) -> SourceProfile:
    return SourceProfile(
        source_id=source_id,
        ssh_alias=f"{source_id}-host",
        allowed_roots=[root],
    )


def _code(error: SourceRegistryError) -> str:
    return error.code.value if hasattr(error.code, "value") else str(error.code)


def test_source_registry_add_list_get_remove_round_trip(tmp_path: Path) -> None:
    registry = SourceRegistry(tmp_path / "sources")
    second = _profile("source-b", "/srv/raw-b")
    first = _profile("source-a", "/srv/raw-a")

    assert registry.list() == []
    assert registry.add(second) == second
    assert registry.add(first) == first

    assert registry.list() == [first, second]
    assert registry.get("source-a") == first
    assert registry.remove("source-a") == first
    assert registry.list() == [second]

    with pytest.raises(SourceRegistryError) as exc_info:
        registry.get("source-a")
    assert _code(exc_info.value) == SourceRegistryErrorCode.SOURCE_NOT_FOUND.value


def test_source_registry_persists_strict_json_without_temp_files(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    registry = SourceRegistry(directory)
    profile = _profile("source-a", "/srv/raw-a")

    registry.add(profile)

    files = list(directory.iterdir())
    assert files == [directory / "source-a.json"]
    assert SourceProfile.model_validate_json(files[0].read_text(encoding="utf-8")) == profile
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert "password" not in payload
    assert "private_key" not in payload
