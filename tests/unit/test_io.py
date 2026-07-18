"""Tests for typed JSON/YAML persistence and atomic replacement."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model, write_model_atomic


class RoundTripModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    name: str
    count: int
    enabled: bool = False


@pytest.mark.parametrize("suffix", [".json", ".yaml", ".yml"])
def test_model_round_trip_by_file_extension(tmp_path: Path, suffix: str) -> None:
    destination = tmp_path / f"artifact{suffix}"
    expected = RoundTripModel(name="synthetic", count=7)

    write_model_atomic(expected, destination)
    actual = read_model(destination, RoundTripModel)

    assert actual == expected


def test_atomic_write_replaces_existing_document_without_temp_files(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "artifact.json"
    original = RoundTripModel(name="before", count=1)
    replacement = RoundTripModel(name="after", count=2, enabled=True)

    write_model_atomic(original, destination)
    write_model_atomic(replacement, destination)

    assert read_model(destination, RoundTripModel) == replacement
    assert list(tmp_path.iterdir()) == [destination]


def test_failed_atomic_replace_preserves_existing_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "artifact.json"
    original = RoundTripModel(name="preserved", count=1)
    replacement = RoundTripModel(name="must-not-appear", count=2)
    write_model_atomic(original, destination)

    def fail_replace(source: object, target: object) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr("biopipe.io.os.replace", fail_replace)

    with pytest.raises(BioPipeError) as exc_info:
        write_model_atomic(replacement, destination)

    assert exc_info.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert read_model(destination, RoundTripModel) == original
    assert list(tmp_path.iterdir()) == [destination]


def test_read_model_rejects_unknown_fields(tmp_path: Path) -> None:
    source = tmp_path / "invalid.json"
    source.write_text(
        '{"schema_version":"1.0","name":"fixture","count":1,"extra":true}',
        encoding="utf-8",
    )

    with pytest.raises(BioPipeError) as exc_info:
        read_model(source, RoundTripModel)

    assert exc_info.value.code is ErrorCode.ARTIFACT_READ_FAILED


@pytest.mark.parametrize(
    ("suffix", "payload"),
    [
        (".json", '{"name":"first","name":"second","count":1}'),
        (".yaml", "name: first\nname: second\ncount: 1\n"),
    ],
)
def test_read_model_rejects_duplicate_mapping_keys(
    tmp_path: Path,
    suffix: str,
    payload: str,
) -> None:
    source = tmp_path / f"duplicate{suffix}"
    source.write_text(payload, encoding="utf-8")

    with pytest.raises(BioPipeError) as captured:
        read_model(source, RoundTripModel)

    assert captured.value.code is ErrorCode.ARTIFACT_READ_FAILED
