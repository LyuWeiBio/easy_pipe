"""Shared JSON/YAML parsing primitives for the controller package.

Duplicate mapping keys and non-finite JSON numbers are rejected everywhere
configuration is parsed; there must be exactly one implementation of each
check — do not fork copies into ``io.py``, ``gate.py``, ``validator.py``,
``client.py``, ``profiles.py``, ``preflight.py``, ``store.py`` or
``registry.py`` again.
"""

from __future__ import annotations

from typing import Any

import yaml

__all__ = [
    "UniqueSafeLoader",
    "reject_constant",
    "unique_object",
]


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects duplicate JSON object keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def reject_constant(value: str) -> Any:
    """``parse_constant`` that rejects non-finite JSON numbers."""
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueSafeLoader,
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


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)
