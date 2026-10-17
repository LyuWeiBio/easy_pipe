"""Unified sanitization gate contracts for release-evidence payloads."""

from __future__ import annotations

import pytest

from biopipe.release_evidence.sanitize import find_forbidden_material


@pytest.mark.parametrize(
    "payload",
    [
        b'{"release_id": "0.1.0-rc1", "status": "ok"}',
        b"total tests: 12 passed in 0.5s",
        b"sha256: " + b"a" * 64,
    ],
)
def test_clean_payloads_pass(payload: bytes) -> None:
    assert find_forbidden_material(payload) is None


@pytest.mark.parametrize(
    "payload",
    [
        b"path: /Users/alice/data",
        b"path: /home/alice/data",
        b"path: /root/.ssh/id_ed25519",
        b"tmpdir: /tmp/biopipe-123",
        b"tmpdir: /var/tmp/work",
        b"tmpdir: /private/tmp/work",
        b"uri: file:///etc/hosts",
        b"win: C:\\\\data\\\\x",
    ],
)
def test_forbidden_path_markers_are_detected(payload: bytes) -> None:
    assert find_forbidden_material(payload) is not None


@pytest.mark.parametrize(
    "payload",
    [
        b"-----BEGIN RSA PRIVATE KEY-----\nabc",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
        b"Authorization: Basic xyz",
        b"Bearer abcdefgh1234",
        b"HMAC_KEY=supersecret",
        b"APPROVAL-KEY: hunter2",
        b"approval.key",
    ],
)
def test_secret_material_is_detected(payload: bytes) -> None:
    assert find_forbidden_material(payload) is not None


@pytest.mark.parametrize("payload", [b"reads.fastq", b"sample.fq", b"token@A0"])
def test_raw_dataset_references_are_detected(payload: bytes) -> None:
    assert find_forbidden_material(payload) is not None


def test_caller_path_fragments_are_detected() -> None:
    fragment = b"/srv/release-candidate-42"
    assert (
        find_forbidden_material(b"built from " + fragment + b"/src", path_fragments=(fragment,))
        is not None
    )
    assert find_forbidden_material(b"built from elsewhere", path_fragments=(fragment,)) is None
    # Empty fragments never match.
    assert find_forbidden_material(b"anything", path_fragments=(b"",)) is None


def test_pending_key_placeholders_are_not_flagged() -> None:
    # Template value placeholders such as HMAC_KEY=PENDING_VALUE must survive
    # the secret-pattern gate (negative lookahead on the value position),
    # matching the release-bundle gate semantics.
    assert find_forbidden_material(b"HMAC_KEY=PENDING_ROTATE_ME") is None
    assert find_forbidden_material(b"APPROVAL_KEY: PENDING_VALUE") is None
