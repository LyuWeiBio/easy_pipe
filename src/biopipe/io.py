"""Strict JSON/YAML model I/O with atomic replacement semantics."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel

from biopipe.errors import BioPipeError, ErrorCode

ModelT = TypeVar("ModelT", bound=BaseModel)
_YAML_SUFFIXES = {".yaml", ".yml"}
_JSON_SUFFIXES = {".json"}


class _UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate mapping key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _format_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in _YAML_SUFFIXES:
        return "yaml"
    if suffix in _JSON_SUFFIXES:
        return "json"
    raise BioPipeError(
        ErrorCode.SERIALIZATION_FAILED,
        "Artifact filename must end in .json, .yaml, or .yml.",
        context={"suffix": suffix},
    )


def _serialized_model(model: BaseModel, format_name: str) -> str:
    data: Any = model.model_dump(mode="json", exclude_none=False)
    if format_name == "json":
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=True)


def write_text_atomic(text: str, path: str | Path) -> None:
    """Write UTF-8 text by fsyncing a sibling temporary file and replacing atomically."""

    destination = Path(path)
    temporary_name: str | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
        assert temporary_name is not None
        os.replace(temporary_name, destination)
    except OSError as exc:
        if temporary_name is not None:
            with suppress(OSError):
                Path(temporary_name).unlink(missing_ok=True)
        raise BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "Could not write the artifact atomically.",
            context={"path": str(destination)},
        ) from exc


def write_model_atomic(model: BaseModel, path: str | Path) -> None:
    """Atomically serialize a Pydantic model according to the destination suffix."""

    destination = Path(path)
    format_name = _format_for(destination)
    write_text_atomic(_serialized_model(model, format_name), destination)


def read_model(path: str | Path, model_type: type[ModelT]) -> ModelT:
    """Load JSON/YAML from *path* and validate it with *model_type*."""

    source = Path(path)
    format_name = _format_for(source)
    try:
        text = source.read_text(encoding="utf-8")
        data = (
            json.loads(text, object_pairs_hook=_unique_object)
            if format_name == "json"
            else yaml.load(text, Loader=_UniqueSafeLoader)
        )
        return model_type.model_validate(data)
    except BioPipeError:
        raise
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "Could not read or validate the artifact.",
            context={"path": str(source), "model": model_type.__name__},
        ) from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


__all__ = ["read_model", "write_model_atomic", "write_text_atomic"]
