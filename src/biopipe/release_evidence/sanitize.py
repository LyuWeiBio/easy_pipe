"""Shared sanitization gate for release-evidence payloads.

The three evidence kinds (sealed release bundles, pilot records, real-host
acceptance) must not embed local-filesystem paths, secret material, or raw
dataset references: evidence is reviewed offline and must be
environment-independent.  The marker set, secret patterns, and path-fragment
matching are unified here so every call site enforces the same semantic;
each caller keeps its own error type and message.
"""

from __future__ import annotations

import re
from typing import Final

# Local user / temp / privileged directories that must never appear in
# evidence.  Kept as byte markers (evidence is bytes) and matched as
# substrings: any occurrence is a leak, regardless of position.
_FORBIDDEN_PATH_MARKERS: Final[tuple[bytes, ...]] = (
    b"/Users/",
    b"/home/",
    b"/root/",
    b"/tmp/",
    b"/var/tmp/",
    b"/private/",
    b"file://",
    b"\\\\",
)
# Literal secret markers (fast path); the regexes below catch variants.
_FORBIDDEN_SECRET_MARKERS: Final[tuple[bytes, ...]] = (
    b"PRIVATE KEY",
    b"Authorization:",
    b"Bearer ",
    b"approval.key",
)
# Raw dataset references that must never leave the source host.
_FORBIDDEN_DATA_MARKERS: Final[tuple[bytes, ...]] = (
    b".fastq",
    b".fq",
    b"@A0",
)
# Generic secret shapes: key blocks, auth headers, bearer tokens, and
# KEY=value assignments for the key families this project uses.  Mirrors the
# release-bundle gate so acceptance evidence gets the same coverage.
_SECRET_PATTERNS: Final[tuple[re.Pattern[bytes], ...]] = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(rb"Authorization\s*:\s*\S+", re.IGNORECASE),
    re.compile(rb"Bearer\s+[A-Za-z0-9._~+/-]{8,}", re.IGNORECASE),
    re.compile(rb"(?:HMAC|SSH|APPROVAL)[_-]?KEY\s*[:=]\s*(?!PENDING_)\S+", re.IGNORECASE),
)

_FORBIDDEN_MARKERS: Final[tuple[bytes, ...]] = (
    *_FORBIDDEN_PATH_MARKERS,
    *_FORBIDDEN_SECRET_MARKERS,
    *_FORBIDDEN_DATA_MARKERS,
)


def find_forbidden_material(
    payload: bytes, *, path_fragments: tuple[bytes, ...] = ()
) -> str | None:
    """Return a short reason when ``payload`` leaks sensitive material.

    ``path_fragments`` are caller-supplied absolute-path byte fragments
    (repository, output, artifact locations); any occurrence is a leak.
    Returns ``None`` when the payload is clean.
    """

    for marker in _FORBIDDEN_MARKERS:
        if marker in payload:
            return f"forbidden marker {marker!r}"
    for pattern in _SECRET_PATTERNS:
        if pattern.search(payload) is not None:
            return "forbidden secret pattern"
    for fragment in path_fragments:
        if fragment and fragment in payload:
            return "forbidden path fragment"
    return None


__all__ = ["find_forbidden_material"]
