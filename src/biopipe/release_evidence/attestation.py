"""HMAC-SHA256 attestation for sealed release-evidence bundles.

A sealed bundle proves *structural* integrity (exact file set, SHA-256 manifest).
The attestation additionally proves *authorship*: the bundle was sealed by a
holder of the controller approval key.  It is an HMAC, not a public-key
signature, so verification requires the same private approval key that created
it -- in practice the release operator's key.  This mirrors the existing
submit/resume/deploy attestation pattern in ``biopipe.execution.signing``.

The attestation covers the exact bytes of the ``SHA256SUMS`` manifest, which
in turn covers every other bundle file.  The attestation file itself is the
only bundle member excluded from the manifest (it cannot cover itself).

Bundles created before attestation existed -- or created without a signer --
verify structurally and are reported as ``unsigned-legacy``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Final, cast

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import ApprovalSigner
from biopipe.execution.signing import load_approval_key

ATTESTATION_NAME: Final[str] = "attestation.json"
ATTESTATION_FORMAT: Final[str] = "biopipe-evidence-attestation/1"
_SIGNING_DOMAIN: Final[bytes] = b"biopipe-evidence-attestation/1\x00"
_MAX_ATTESTATION_BYTES: Final[int] = 4096
_HEX_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")


def create_attestation(*, manifest_bytes: bytes, signer: ApprovalSigner) -> bytes:
    """Return the canonical ``attestation.json`` payload for a sealed bundle."""

    key = load_approval_key(signer)
    signature = hmac.new(key, _SIGNING_DOMAIN + manifest_bytes, hashlib.sha256)
    payload = {
        "format": ATTESTATION_FORMAT,
        "key_id": signer.key_id,
        "signature": signature.hexdigest(),
    }
    return _render_attestation(payload)


def verify_attestation(
    *, manifest_bytes: bytes, attestation: bytes, signer: ApprovalSigner
) -> None:
    """Verify an attestation against the manifest bytes; raise on any mismatch."""

    payload = _decode_attestation(attestation)
    key_id = payload.get("key_id")
    signature = payload.get("signature")
    if key_id != signer.key_id:
        raise _attestation_error("attestation key identifier does not match the signer")
    if not isinstance(signature, str) or not _HEX_SIGNATURE.fullmatch(signature):
        raise _attestation_error("attestation signature is malformed")
    key = load_approval_key(signer)
    expected = hmac.new(key, _SIGNING_DOMAIN + manifest_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise _attestation_error("attestation signature does not match the manifest")


def _render_attestation(payload: dict[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise _attestation_error("attestation payload could not be serialized") from exc


def _decode_attestation(payload: bytes) -> dict[str, Any]:
    if not 0 < len(payload) <= _MAX_ATTESTATION_BYTES:
        raise _attestation_error("attestation payload has an invalid size")

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _attestation_error("attestation payload is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"format", "key_id", "signature"}:
        raise _attestation_error("attestation payload has an unexpected shape")
    if value.get("format") != ATTESTATION_FORMAT:
        raise _attestation_error("attestation format is unsupported")
    return cast(dict[str, Any], value)


def _attestation_error(reason: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "Release evidence attestation is missing or invalid.",
        context={"reason": reason},
        remediation=[
            "Create the bundle with the reviewed private approval key to sign it, "
            "or verify with the same key that sealed the bundle."
        ],
    )


__all__ = [
    "ATTESTATION_FORMAT",
    "ATTESTATION_NAME",
    "create_attestation",
    "verify_attestation",
]
