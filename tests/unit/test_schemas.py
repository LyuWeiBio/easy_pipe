"""Tests for deterministic export of every public JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import PUBLIC_MODELS
from biopipe.schemas import export_json_schemas

EXPECTED_SCHEMA_NAMES = {
    "AuditEvent.schema.json",
    "DatasetManifest.schema.json",
    "ExecutionPlan.schema.json",
    "ManifestOverrides.schema.json",
    "PipelineSpec.schema.json",
    "ProbeRequest.schema.json",
    "ProbeResponse.schema.json",
    "SoftwareLock.schema.json",
    "SourceProfile.schema.json",
}


def test_export_json_schemas_writes_all_public_models(tmp_path: Path) -> None:
    expected_names = {f"{model.__name__}.schema.json" for model in PUBLIC_MODELS}

    written = export_json_schemas(tmp_path)

    assert expected_names == EXPECTED_SCHEMA_NAMES
    assert len(written) == len(EXPECTED_SCHEMA_NAMES)
    assert {path.name for path in written} == expected_names
    assert {path.name for path in tmp_path.iterdir()} == expected_names
    for model, path in zip(PUBLIC_MODELS, written, strict=True):
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["title"] == model.__name__
        assert schema["additionalProperties"] is False


def test_export_json_schemas_is_deterministic_and_leaves_no_temp_files(
    tmp_path: Path,
) -> None:
    first_paths = export_json_schemas(tmp_path)
    first_contents = {path.name: path.read_bytes() for path in first_paths}

    second_paths = export_json_schemas(tmp_path)
    second_contents = {path.name: path.read_bytes() for path in second_paths}

    assert second_paths == first_paths
    assert second_contents == first_contents
    assert all(path.suffix == ".json" for path in tmp_path.iterdir())


def test_failed_schema_replace_preserves_existing_exports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = export_json_schemas(tmp_path)
    original_contents = {path.name: path.read_bytes() for path in paths}

    def fail_replace(source: object, target: object) -> None:
        raise OSError("synthetic schema replace failure")

    monkeypatch.setattr("biopipe.io.os.replace", fail_replace)

    with pytest.raises(BioPipeError) as exc_info:
        export_json_schemas(tmp_path)

    assert exc_info.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert {path.name: path.read_bytes() for path in paths} == original_contents
    assert {path.name for path in tmp_path.iterdir()} == set(original_contents)
