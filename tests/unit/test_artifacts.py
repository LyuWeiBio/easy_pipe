"""Tests for deterministic artifact hashing."""

from __future__ import annotations

from pathlib import Path

from biopipe.artifacts import sha256_file


def test_sha256_file_matches_known_digest(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"abc")

    assert sha256_file(artifact) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_hashes_empty_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "empty"
    artifact.write_bytes(b"")

    assert sha256_file(artifact) == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
