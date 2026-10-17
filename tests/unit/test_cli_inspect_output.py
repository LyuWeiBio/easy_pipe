"""Regression tests for `biopipe inspect --output` path handling."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import biopipe.cli.inspect as inspect_cli
from biopipe.errors import BioPipeError, ErrorCode


def _patch_inspect_command(monkeypatch, tmp_path: Path) -> dict:
    """Stub the registry, probe client, and artifact store around inspect_command."""

    monkeypatch.setenv("HOME", str(tmp_path))
    profile = SimpleNamespace(
        source_id="hpc01",
        probe=SimpleNamespace(max_response_bytes=1024, stderr_limit_bytes=1024),
    )
    monkeypatch.setattr(
        inspect_cli, "SourceRegistry", lambda base: SimpleNamespace(get=lambda _sid: profile)
    )
    monkeypatch.setattr(
        inspect_cli, "OpenSSHProbeClient", lambda **_kwargs: SimpleNamespace()
    )
    manifest = SimpleNamespace(errors=[])
    monkeypatch.setattr(inspect_cli, "inspect_fastq_dataset", lambda *a, **k: manifest)
    monkeypatch.setattr(inspect_cli, "sanitize_manifest", lambda _m: "sanitized")
    monkeypatch.setattr(inspect_cli, "render_samplesheet", lambda _m: "csv")
    monkeypatch.setattr(inspect_cli, "emit", lambda *a, **k: None)

    created: dict = {}

    class FakeStore:
        def __init__(self, parent: Path) -> None:
            created["parent"] = parent

        def create_bundle(self, artifacts: dict) -> None:
            created["artifacts"] = artifacts

    monkeypatch.setattr(inspect_cli, "ManifestArtifactStore", FakeStore)
    return created


def test_inspect_output_tilde_is_expanded_not_literal(
    monkeypatch, tmp_path: Path
) -> None:
    created = _patch_inspect_command(monkeypatch, tmp_path)
    inspect_cli.inspect_command(
        target="hpc01:/data/raw",
        policy="format-summary",
        output=Path("~/out/manifest.json"),
        config_dir=tmp_path / "config",
        dry_run=False,
    )
    assert created["parent"] == tmp_path / "out"
    # The bug created a literal "~" directory under the working directory.
    assert not (Path.cwd() / "~").exists()


def test_inspect_output_metadata_only_tilde_is_expanded(
    monkeypatch, tmp_path: Path
) -> None:
    import json as json_module

    created: dict = {}
    _patch_inspect_command(monkeypatch, tmp_path)

    class FakeTextStore:
        def __init__(self, parent: Path) -> None:
            created["parent"] = parent

        def create_text(self, name: str, payload: str) -> None:
            created["name"] = name
            created["payload"] = payload

    monkeypatch.setattr(inspect_cli, "ManifestArtifactStore", FakeTextStore)
    response = SimpleNamespace(
        model_dump=lambda mode: {"root": "/data/raw"},
    )

    def _client(**kwargs):
        return SimpleNamespace(list_tree=lambda profile, root: response)

    monkeypatch.setattr(inspect_cli, "OpenSSHProbeClient", _client)
    inspect_cli.inspect_command(
        target="hpc01:/data/raw",
        policy="metadata-only",
        output=Path("~/out/tree.json"),
        config_dir=tmp_path / "config",
        dry_run=False,
    )
    assert created["parent"] == tmp_path / "out"
    assert created["name"] == "tree.json"
    assert json_module.loads(created["payload"]) == {"root": "/data/raw"}


@pytest.mark.parametrize(
    "target",
    [
        "hpc01:relative/path",
        "hpc 01:/data/raw",
        "../evil:/data/raw",
        "hpc01:",
        ":",
        "hpc01",
    ],
)
def test_split_target_rejects_malformed_targets(target: str) -> None:
    """P3 #25: _split_target pre-validates source id and absolute root."""
    with pytest.raises(BioPipeError) as caught:
        inspect_cli._split_target(target)
    assert caught.value.code is ErrorCode.VALIDATION_FAILED


def test_split_target_accepts_well_formed_target() -> None:
    assert inspect_cli._split_target("hpc01:/data/raw") == ("hpc01", "/data/raw")
