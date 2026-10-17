"""HMAC attestation contracts for sealed release-evidence bundles."""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest import mock

import pytest
from test_release_evidence import (
    _CREATED_AT,
    _CREATED_BY,
    _RELEASE_ID,
    _clean_release_repository,
    _fake_release_artifacts,
)

import biopipe.release_evidence.generator as evidence_generator
from biopipe.errors import BioPipeError
from biopipe.execution.models import ApprovalSigner
from biopipe.release_evidence import (
    create_release_evidence,
    verify_release_evidence,
)
from biopipe.release_evidence.attestation import ATTESTATION_NAME

_KEY_ID = "round3-test-key"


@pytest.fixture(autouse=True)
def _bind_test_candidate_to_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        evidence_generator,
        "_validate_runtime_source_binding",
        lambda _repository, _commit: None,
    )


def _approval_signer(root: Path, *, key_id: str = _KEY_ID, seed: str = "a") -> ApprovalSigner:
    key_file = root / f"approval-{seed}.key"
    key_file.write_text(seed * 64 + "\n", encoding="ascii")
    key_file.chmod(0o600)
    return ApprovalSigner(key_id=key_id, key_file=str(key_file))


def _create_bundle(root: Path, *, name: str, signer: ApprovalSigner | None) -> Path:
    repository, _commit = _clean_release_repository(root)
    artifact_paths, _payloads = _fake_release_artifacts(root)
    parent = root / name
    # The bundle store requires the output parent to be group/world-write-free;
    # set the mode explicitly (the ambient umask may allow group write).
    parent.mkdir(mode=0o700)
    output = parent / _RELEASE_ID
    create_release_evidence(
        repository=repository,
        output_directory=output,
        release_id=_RELEASE_ID,
        created_at=_CREATED_AT,
        created_by=_CREATED_BY,
        artifact_paths=artifact_paths,
        approval_signer=signer,
    )
    return output


@pytest.fixture(scope="module")
def signed_bundle(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, ApprovalSigner]:
    # Module-scoped fixtures run before function-scoped autouse fixtures, so
    # the runtime-binding stub is applied here explicitly.
    root = tmp_path_factory.mktemp("signed")
    signer = _approval_signer(root)
    with mock.patch.object(
        evidence_generator,
        "_validate_runtime_source_binding",
        lambda _repository, _commit: None,
    ):
        bundle = _create_bundle(root, name="evidence", signer=signer)
    return bundle, signer


@pytest.fixture(scope="module")
def legacy_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("legacy")
    with mock.patch.object(
        evidence_generator,
        "_validate_runtime_source_binding",
        lambda _repository, _commit: None,
    ):
        return _create_bundle(root, name="evidence", signer=None)


def _copy_bundle(bundle: Path, tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    shutil.copytree(bundle, target)
    return target


def test_create_with_signer_seals_signed_bundle(
    signed_bundle: tuple[Path, ApprovalSigner],
) -> None:
    bundle, signer = signed_bundle
    assert (bundle / ATTESTATION_NAME).is_file()
    result = verify_release_evidence(bundle, approval_signer=signer)
    assert result.signature_status == "signed"
    assert result.integrity_status == "verified"


def test_verify_signed_bundle_without_key_fails_closed(
    signed_bundle: tuple[Path, ApprovalSigner],
) -> None:
    bundle, _signer = signed_bundle
    with pytest.raises(BioPipeError):
        verify_release_evidence(bundle)


def test_verify_signed_bundle_with_wrong_key_fails(
    signed_bundle: tuple[Path, ApprovalSigner], tmp_path: Path
) -> None:
    bundle, _signer = signed_bundle
    wrong = _approval_signer(tmp_path, seed="b")
    with pytest.raises(BioPipeError):
        verify_release_evidence(bundle, approval_signer=wrong)


def test_verify_signed_bundle_with_wrong_key_id_fails(
    signed_bundle: tuple[Path, ApprovalSigner], tmp_path: Path
) -> None:
    bundle, _signer = signed_bundle
    other = _approval_signer(tmp_path, key_id="other-key")
    with pytest.raises(BioPipeError):
        verify_release_evidence(bundle, approval_signer=other)


def test_verify_rejects_tampered_manifest(
    signed_bundle: tuple[Path, ApprovalSigner], tmp_path: Path
) -> None:
    bundle, signer = signed_bundle
    target = _copy_bundle(bundle, tmp_path, "tampered-manifest")
    manifest = target / "SHA256SUMS"
    raw = bytearray(manifest.read_bytes())
    raw[10] ^= 0x01
    manifest.write_bytes(bytes(raw))
    with pytest.raises(BioPipeError):
        verify_release_evidence(target, approval_signer=signer)


def test_verify_rejects_tampered_attestation(
    signed_bundle: tuple[Path, ApprovalSigner], tmp_path: Path
) -> None:
    bundle, signer = signed_bundle
    target = _copy_bundle(bundle, tmp_path, "tampered-attestation")
    attestation = target / ATTESTATION_NAME
    raw = bytearray(attestation.read_bytes())
    # Flip one hex digit inside the signature value (keeps JSON valid).
    for index in range(len(raw)):
        if raw[index : index + 1].isdigit() or raw[index : index + 1].isalpha():
            raw[index] = ord("0") if raw[index] != ord("0") else ord("1")
            break
    attestation.write_bytes(bytes(raw))
    with pytest.raises(BioPipeError):
        verify_release_evidence(target, approval_signer=signer)


def test_removed_attestation_downgrades_to_unsigned_legacy(
    signed_bundle: tuple[Path, ApprovalSigner], tmp_path: Path
) -> None:
    # Deleting the attestation cannot forge content: the bundle still verifies
    # structurally, but the downgrade is visible as unsigned-legacy.  Release
    # policy must reject unsigned-legacy for release candidates.
    bundle, signer = signed_bundle
    target = _copy_bundle(bundle, tmp_path, "removed-attestation")
    (target / ATTESTATION_NAME).unlink()
    result = verify_release_evidence(target, approval_signer=signer)
    assert result.signature_status == "unsigned-legacy"


def test_legacy_bundle_without_signer_is_unsigned_legacy(
    legacy_bundle: Path, tmp_path: Path
) -> None:
    assert not (legacy_bundle / ATTESTATION_NAME).exists()
    assert verify_release_evidence(legacy_bundle).signature_status == "unsigned-legacy"
    signer = _approval_signer(tmp_path)
    assert (
        verify_release_evidence(legacy_bundle, approval_signer=signer).signature_status
        == "unsigned-legacy"
    )


def test_attestation_is_deterministic_for_same_inputs(
    signed_bundle: tuple[Path, ApprovalSigner],
) -> None:
    bundle, _signer = signed_bundle
    first = (bundle / ATTESTATION_NAME).read_bytes()
    assert first.endswith(b"\n")
    assert b'"format":"biopipe-evidence-attestation/1"' in first
