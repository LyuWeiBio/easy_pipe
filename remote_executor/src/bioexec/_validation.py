"""Shared contract-validation primitives for the scheduler subsystem.

The scheduler's contract modules (``config``, ``scheduler_config``,
``scheduler_run``, ``scheduler_state``, ``scheduler_preflight``) all
validate untrusted JSON against the same shapes.  The *checks* live here
exactly once — do not fork copies back into those modules.

``scheduler_protocol`` is intentionally excluded: it must stay importable
with only the standard library plus ``.slurm`` (enforced by
``test_scheduler_protocol_uses_only_stdlib_and_pure_slurm_contract_imports``),
so it keeps its own local copies.

Each module keeps its own domain error type and message wording; the
predicates below answer only "is this value valid", while the small
``canonical_json_bytes`` / ``reject_constant`` / ``reject_excessive_nesting``
/ ``unique_object`` helpers raise :class:`ValueError` for callers to
translate.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

__all__ = [
    "MAX_JSON_NESTING",
    "canonical_json_bytes",
    "has_exact_fields",
    "is_safe_identifier",
    "is_sha256_digest",
    "is_strict_int",
    "reject_constant",
    "reject_excessive_nesting",
    "shell_quote",
    "unique_object",
]

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ZERO_DIGEST = "0" * 64

MAX_JSON_NESTING = 128


def is_safe_identifier(value: Any) -> bool:
    """Return True when ``value`` is a bounded safe identifier."""
    return isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value) is not None


def is_sha256_digest(value: Any, *, reject_zero: bool = False) -> bool:
    """Return True when ``value`` is a lowercase SHA-256 hex digest."""
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        return False
    return not (reject_zero and value == _ZERO_DIGEST)


def is_strict_int(value: Any, minimum: int, maximum: int) -> bool:
    """Return True when ``value`` is a genuine int (not bool) inside range.

    ``type(value) is int`` is deliberate: ``bool`` is a subclass of ``int``
    and must never pass as a contract integer.
    """
    return type(value) is int and minimum <= value <= maximum


def has_exact_fields(value: Mapping[str, Any], fields: set[str] | frozenset[str]) -> bool:
    """Return True when ``value``'s keys are exactly ``fields``."""
    return set(value) == set(fields)


def canonical_json_bytes(value: Any, *, trailing_newline: bool = False) -> bytes:
    """Serialize ``value`` to canonical JSON bytes (sorted keys, ASCII).

    Raises :class:`ValueError` when the value cannot be canonically
    serialized.  ``trailing_newline`` selects the durable-record form that
    ends with a single ``\\n``.
    """
    try:
        text = json.dumps(
            dict(value) if isinstance(value, Mapping) else value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("value cannot be canonically serialized") from exc
    if trailing_newline:
        text += "\n"
    try:
        return text.encode("ascii")
    except UnicodeError as exc:  # pragma: no cover - ensure_ascii=True guards this
        raise ValueError("value cannot be canonically serialized") from exc


def reject_constant(value: str, *, message: str = "non-finite JSON number is forbidden") -> Any:
    """``parse_constant`` hook rejecting non-finite JSON numbers."""
    raise ValueError(f"{message}: {value}")


def reject_excessive_nesting(text: str, *, maximum: int = MAX_JSON_NESTING) -> None:
    """Reject JSON text nested deeper than ``maximum`` without parsing it."""
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise ValueError("JSON nesting exceeds the supported limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("JSON delimiters are unbalanced")
    if depth != 0 or in_string:
        raise ValueError("JSON structure is incomplete")


def unique_object(
    pairs: list[tuple[str, Any]], *, duplicate_message: str = "duplicate JSON object key"
) -> dict[str, Any]:
    """``object_pairs_hook`` rejecting duplicate keys with a custom message."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(duplicate_message)
        result[key] = value
    return result


def shell_quote(value: str) -> str:
    """Quote ``value`` for POSIX shell as a single-quoted word.

    Rejects empty values, NUL bytes, control text, and non-ASCII so the
    result is shell-inert.  Raises :class:`ValueError` for unsafe values;
    callers translate it into their domain error type.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("shell word is empty or contains NUL")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("shell word contains control text")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("shell word must be shell-inert ASCII") from exc
    return "'" + value.replace("'", "'\"'\"'" ) + "'"
