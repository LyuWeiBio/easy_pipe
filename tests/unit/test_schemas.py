"""Tests for deterministic export of every public JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.schemas import (
    JSON_SCHEMA_DIALECT,
    MVP_SCHEMA_MODELS,
    export_json_schemas,
    render_runtime_catalog,
    render_runtime_schema,
    schema_catalog,
    schema_for,
    schema_name,
)
from biopipe.version import MVP_SCHEMA_VERSION

_VERSION_FIELDS = {
    "AuditEvent": "schema_version",
    "DatasetManifest": "manifest_version",
    "ExecutionPlan": "plan_version",
    "ExecutionProfile": "profile_version",
    "ManifestOverrides": "override_version",
    "OverrideDiff": "diff_version",
    "PipelineSpec": "spec_version",
    "PreflightReport": "report_version",
    "ProbeRequest": "protocol_version",
    "ProbeResponse": "protocol_version",
    "ReconciliationReport": "report_version",
    "RegistryDocument": "registry_schema_version",
    "RunAuthorization": "authorization_version",
    "RunReport": "report_version",
    "SoftwareLock": "lock_version",
    "SourceProfile": "schema_version",
    "StatusReport": "report_version",
    "TestCommandReport": "report_version",
    "ValidationCommandReport": "report_version",
    "ValidationReport": "report_version",
    "WorkflowTestReport": "report_version",
}
_PACKAGE_SCHEMA_DIRECTORY = Path("src/biopipe/schema_v1")
_GOLDEN_SCHEMA_DIRECTORY = Path("tests/fixtures/schema_v1")


def test_export_json_schemas_writes_all_public_models(tmp_path: Path) -> None:
    expected_names = {f"{model.__name__}.schema.json" for model in MVP_SCHEMA_MODELS}

    written = export_json_schemas(tmp_path)

    assert set(_VERSION_FIELDS) == {model.__name__ for model in MVP_SCHEMA_MODELS}
    assert len(written) == len(expected_names) + 1
    assert {path.name for path in written} == expected_names | {"catalog.json"}
    assert {path.name for path in tmp_path.iterdir()} == expected_names | {"catalog.json"}
    for model, path in zip(MVP_SCHEMA_MODELS, written[:-1], strict=True):
        assert path.read_bytes() == (_PACKAGE_SCHEMA_DIRECTORY / path.name).read_bytes()
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["title"] == model.__name__
        assert schema["additionalProperties"] is False
        assert schema["$schema"] == JSON_SCHEMA_DIALECT
        assert schema["x-biopipe-schema-version"] == MVP_SCHEMA_VERSION
        version_schema = schema["properties"][_VERSION_FIELDS[model.__name__]]
        assert version_schema["const"] == MVP_SCHEMA_VERSION
        assert version_schema["default"] == MVP_SCHEMA_VERSION


def test_installed_and_golden_v1_sets_are_exact_and_runtime_compatible() -> None:
    expected_names = {schema_name(model) for model in MVP_SCHEMA_MODELS} | {"catalog.json"}
    package_names = {path.name for path in _PACKAGE_SCHEMA_DIRECTORY.iterdir() if path.is_file()}
    golden_names = {path.name for path in _GOLDEN_SCHEMA_DIRECTORY.iterdir() if path.is_file()}

    assert len(MVP_SCHEMA_MODELS) == 21
    assert package_names == golden_names == expected_names

    schema_bytes: dict[str, bytes] = {}
    for model in MVP_SCHEMA_MODELS:
        name = schema_name(model)
        installed = (_PACKAGE_SCHEMA_DIRECTORY / name).read_bytes()
        golden = (_GOLDEN_SCHEMA_DIRECTORY / name).read_bytes()
        runtime = render_runtime_schema(model)
        assert installed == golden == runtime
        assert schema_for(model) == json.loads(installed)
        schema_bytes[name] = installed

    installed_catalog = (_PACKAGE_SCHEMA_DIRECTORY / "catalog.json").read_bytes()
    golden_catalog = (_GOLDEN_SCHEMA_DIRECTORY / "catalog.json").read_bytes()
    runtime_catalog = render_runtime_catalog(schema_bytes)

    assert installed_catalog == golden_catalog == runtime_catalog
    assert schema_catalog() == json.loads(installed_catalog)


def test_schema_for_rejects_models_outside_frozen_catalog() -> None:
    from pydantic import BaseModel

    class NotPublic(BaseModel):
        value: str

    with pytest.raises(ValueError, match="not part of the frozen MVP"):
        schema_for(NotPublic)


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
