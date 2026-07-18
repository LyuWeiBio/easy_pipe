"""Canonical integrity handling for immutable dataset manifests."""

from __future__ import annotations

import hashlib
import json

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import DatasetManifest, ManifestIntegrity


def canonical_manifest_bytes(manifest: DatasetManifest) -> bytes:
    """Return the canonical representation used by the embedded digest."""

    payload = manifest.model_dump(mode="json", exclude_none=False)
    payload["integrity"] = {"manifest_sha256": None}
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def manifest_sha256(manifest: DatasetManifest) -> str:
    """Hash a manifest independently of its embedded digest field."""

    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def finalize_manifest(manifest: DatasetManifest) -> DatasetManifest:
    """Return a deep copy with its canonical SHA-256 embedded."""

    digest = manifest_sha256(manifest)
    return manifest.model_copy(
        update={"integrity": ManifestIntegrity(manifest_sha256=digest)},
        deep=True,
    )


def verify_manifest(manifest: DatasetManifest) -> bool:
    """Return whether the embedded digest matches the canonical content."""

    embedded = manifest.integrity.manifest_sha256
    return embedded is not None and embedded == manifest_sha256(manifest)


def require_valid_manifest(manifest: DatasetManifest) -> DatasetManifest:
    """Reject an unsigned or modified manifest at an artifact trust boundary."""

    if not verify_manifest(manifest):
        raise BioPipeError(
            ErrorCode.MANIFEST_INTEGRITY_FAILED,
            "The dataset manifest digest is missing or does not match its content.",
            remediation=["Recreate the manifest from the original scan artifact."],
        )
    return manifest


__all__ = [
    "canonical_manifest_bytes",
    "finalize_manifest",
    "manifest_sha256",
    "require_valid_manifest",
    "verify_manifest",
]
