"""Installed, frozen JSON Schema v1 catalog and runtime parity helpers."""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path
from typing import Final, cast

from pydantic import BaseModel

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import ExecutionProfile, PreflightReport, RunAuthorization
from biopipe.execution.reports import ReconciliationReport, RunReport, StatusReport
from biopipe.io import write_text_atomic
from biopipe.manifests import OverrideDiff
from biopipe.models import PUBLIC_MODELS
from biopipe.registry.models import RegistryDocument
from biopipe.report_models import TestCommandReport, ValidationCommandReport
from biopipe.validation import ValidationReport
from biopipe.version import MVP_SCHEMA_VERSION
from biopipe.workflow_test import WorkflowTestReport

JSON_SCHEMA_DIALECT: Final[str] = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_BASE: Final[str] = "https://github.com/LyuWeiBio/easy_pipe/schemas/v1"
_SCHEMA_RESOURCE_DIRECTORY: Final[str] = "schema_v1"
_MAX_SCHEMA_BYTES: Final[int] = 4 * 1024 * 1024

MVP_SCHEMA_MODELS: Final[tuple[type[BaseModel], ...]] = tuple(
    sorted(
        (
            *PUBLIC_MODELS,
            ExecutionProfile,
            OverrideDiff,
            PreflightReport,
            ReconciliationReport,
            RegistryDocument,
            RunAuthorization,
            RunReport,
            StatusReport,
            TestCommandReport,
            ValidationCommandReport,
            ValidationReport,
            WorkflowTestReport,
        ),
        key=lambda model: model.__name__,
    )
)
_MODEL_BY_NAME: Final[dict[str, type[BaseModel]]] = {
    model.__name__: model for model in MVP_SCHEMA_MODELS
}


def schema_name(model: type[BaseModel]) -> str:
    """Return the stable public filename for one contract model."""

    return f"{model.__name__}.schema.json"


def runtime_schema_for(model: type[BaseModel]) -> dict[str, object]:
    """Generate a schema only for CI parity checks against installed v1 bytes."""

    if model not in MVP_SCHEMA_MODELS:
        raise ValueError("model is not part of the frozen MVP schema catalog")
    schema: dict[str, object] = model.model_json_schema()
    schema["$id"] = f"{SCHEMA_ID_BASE}/{schema_name(model)}"
    schema["$schema"] = JSON_SCHEMA_DIALECT
    schema["x-biopipe-schema-version"] = MVP_SCHEMA_VERSION
    return schema


def render_runtime_schema(model: type[BaseModel]) -> bytes:
    """Render the canonical bytes that must match the committed v1 resource."""

    return (
        json.dumps(
            runtime_schema_for(model),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def schema_for(model: type[BaseModel]) -> dict[str, object]:
    """Load one public schema from the installed immutable v1 resources."""

    if model not in MVP_SCHEMA_MODELS:
        raise ValueError("model is not part of the frozen MVP schema catalog")
    return _load_frozen_json(schema_name(model))


def schema_by_name(name: str) -> dict[str, object]:
    """Load one frozen catalog schema selected by model or schema filename."""

    normalized = name.removesuffix(".schema.json")
    try:
        model = _MODEL_BY_NAME[normalized]
    except KeyError as exc:
        raise ValueError("unknown public schema") from exc
    return schema_for(model)


def schema_catalog() -> dict[str, object]:
    """Load the installed, hash-stable machine-readable v1 catalog."""

    catalog = _load_frozen_json("catalog.json")
    if catalog.get("schema_version") != MVP_SCHEMA_VERSION:
        raise _schema_resource_error("catalog.json")
    return catalog


def build_runtime_catalog(schema_bytes: dict[str, bytes]) -> dict[str, object]:
    """Build canonical catalog data for release tooling and parity tests."""

    expected_names = {schema_name(model) for model in MVP_SCHEMA_MODELS}
    if set(schema_bytes) != expected_names:
        raise ValueError("runtime schema byte set is incomplete")
    entries: list[dict[str, str]] = []
    aggregate = hashlib.sha256()
    for name in sorted(schema_bytes):
        payload = schema_bytes[name]
        model_name = name.removesuffix(".schema.json")
        aggregate.update(name.encode("ascii"))
        aggregate.update(b"\0")
        aggregate.update(payload)
        entries.append(
            {
                "id": f"{SCHEMA_ID_BASE}/{name}",
                "name": model_name,
                "path": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "catalog_sha256": aggregate.hexdigest(),
        "schema_count": len(entries),
        "schema_version": MVP_SCHEMA_VERSION,
        "schemas": entries,
    }


def render_runtime_catalog(schema_bytes: dict[str, bytes]) -> bytes:
    """Render canonical catalog bytes for release tooling."""

    return (
        json.dumps(
            build_runtime_catalog(schema_bytes),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def export_json_schemas(output_dir: str | Path) -> tuple[Path, ...]:
    """Copy exact installed v1 schema bytes to a selected directory."""

    destination = Path(output_dir)
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "The schema export directory could not be created.",
            remediation=["Choose a writable, non-symlink schema output directory."],
        ) from exc
    names = [schema_name(model) for model in MVP_SCHEMA_MODELS]
    names.append("catalog.json")
    written: list[Path] = []
    for name in names:
        path = destination / name
        payload = _load_frozen_bytes(name)
        try:
            text = payload.decode("utf-8")
        except UnicodeError as exc:
            raise _schema_resource_error(name) from exc
        write_text_atomic(text, path)
        written.append(path)
    return tuple(written)


def _load_frozen_json(name: str) -> dict[str, object]:
    payload = _load_frozen_bytes(name)
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise _schema_resource_error(name) from exc
    if not isinstance(parsed, dict):
        raise _schema_resource_error(name)
    return cast(dict[str, object], parsed)


def _load_frozen_bytes(name: str) -> bytes:
    if name != "catalog.json" and name not in {schema_name(model) for model in MVP_SCHEMA_MODELS}:
        raise _schema_resource_error(name)
    try:
        payload = (
            resources.files("biopipe")
            .joinpath(_SCHEMA_RESOURCE_DIRECTORY)
            .joinpath(name)
            .read_bytes()
        )
    except (FileNotFoundError, OSError) as exc:
        raise _schema_resource_error(name) from exc
    if not 0 < len(payload) <= _MAX_SCHEMA_BYTES:
        raise _schema_resource_error(name)
    return payload


def _schema_resource_error(name: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.ARTIFACT_READ_FAILED,
        "An installed frozen schema resource is missing or invalid.",
        context={"schema": name},
        remediation=["Reinstall the reviewed easy-pipe distribution."],
    )


__all__ = [
    "JSON_SCHEMA_DIALECT",
    "MVP_SCHEMA_MODELS",
    "SCHEMA_ID_BASE",
    "build_runtime_catalog",
    "export_json_schemas",
    "render_runtime_catalog",
    "render_runtime_schema",
    "runtime_schema_for",
    "schema_by_name",
    "schema_catalog",
    "schema_for",
    "schema_name",
]
