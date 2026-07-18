"""M2 CLI integration for manifest inspection and override artifacts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from biopipe.cli.app import app
from biopipe.io import write_model_atomic
from biopipe.manifests import finalize_manifest, verify_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetSample,
    LaneFiles,
    ManifestOverrides,
    ManifestSource,
    SourceProfile,
)
from biopipe.sources import SourceRegistry

runner = CliRunner()
ROOT = "/srv/synthetic-raw"


def _profile() -> SourceProfile:
    return SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=[ROOT],
    )


def _manifest() -> DatasetManifest:
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="synthetic-source",
                root=ROOT,
                scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                scan_policy="format_summary",
            ),
            classification=DatasetClassification(
                dataset_type="generic_fastq",
                layout="single_end",
                confidence=0.95,
            ),
            samples=[
                DatasetSample(
                    sample_id="sample_001",
                    original_sample_name="Sensitive-A",
                    lanes=[
                        LaneFiles(
                            read1=f"{ROOT}/Sensitive-A.fastq.gz",
                        )
                    ],
                )
            ],
        )
    )


def test_format_summary_inspect_writes_full_sanitized_and_samplesheet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "controller"
    SourceRegistry(config_dir / "sources").add(_profile())
    output = tmp_path / "dataset.manifest.json"
    fake_client = object()

    class FakeClient:
        def __new__(cls, **limits: object) -> object:
            assert limits
            return fake_client

    def fake_inspection(
        profile: SourceProfile,
        root: str,
        *,
        client: object,
        sample_fastq_records: int,
    ) -> DatasetManifest:
        assert profile.source_id == "synthetic-source"
        assert root == ROOT
        assert client is fake_client
        assert sample_fastq_records == 25
        return _manifest()

    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", FakeClient)
    monkeypatch.setattr("biopipe.cli.inspect.inspect_fastq_dataset", fake_inspection)

    result = runner.invoke(
        app,
        [
            "inspect",
            f"synthetic-source:{ROOT}",
            "--policy",
            "format-summary",
            "--sample-fastq-records",
            "25",
            "--output",
            str(output),
            "--config-dir",
            str(config_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    full = DatasetManifest.model_validate_json(output.read_text(encoding="utf-8"))
    assert verify_manifest(full)
    sanitized_text = (tmp_path / "dataset.manifest.sanitized.json").read_text(encoding="utf-8")
    assert "Sensitive-A" not in sanitized_text
    assert (tmp_path / "dataset.manifest.samplesheet.csv").is_file()
    assert json.loads(result.stdout)["integrity"]["manifest_sha256"] == (
        full.integrity.manifest_sha256
    )


def test_manifest_show_and_apply_overrides_preserve_original(tmp_path: Path) -> None:
    manifest_path = tmp_path / "dataset.manifest.json"
    overrides_path = tmp_path / "dataset.overrides.json"
    output_dir = tmp_path / "resolved"
    write_model_atomic(_manifest(), manifest_path)
    write_model_atomic(
        ManifestOverrides(
            rename_samples={"Sensitive-A": "control_01"},
            reason="Synthetic reviewed rename.",
            approved_by="pytest-user",
        ),
        overrides_path,
    )
    original_text = manifest_path.read_text(encoding="utf-8")

    shown = runner.invoke(app, ["manifest", "show", str(manifest_path), "--json"])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.stdout)["sample_count"] == 1

    applied = runner.invoke(
        app,
        [
            "manifest",
            "apply-overrides",
            str(manifest_path),
            "--overrides",
            str(overrides_path),
            "--output-dir",
            str(output_dir),
            "--name",
            "reviewed",
            "--json",
        ],
    )

    assert applied.exit_code == 0, applied.output
    assert manifest_path.read_text(encoding="utf-8") == original_text
    resolved = DatasetManifest.model_validate_json(
        (output_dir / "reviewed.manifest.resolved.json").read_text(encoding="utf-8")
    )
    assert verify_manifest(resolved)
    assert resolved.samples[0].sample_id == "control_01"
    assert (output_dir / "reviewed.override.applied.json").is_file()
    assert (output_dir / "reviewed.override.diff.json").is_file()
    assert (output_dir / "reviewed.samplesheet.csv").is_file()


def test_inspect_bundle_conflict_does_not_leave_first_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "controller"
    SourceRegistry(config_dir / "sources").add(_profile())
    output = tmp_path / "dataset.manifest.json"
    conflict = tmp_path / "dataset.manifest.sanitized.json"
    conflict.write_text("existing artifact\n", encoding="utf-8")

    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", lambda **_limits: object())
    monkeypatch.setattr(
        "biopipe.cli.inspect.inspect_fastq_dataset",
        lambda *_args, **_kwargs: _manifest(),
    )

    result = runner.invoke(
        app,
        [
            "inspect",
            f"synthetic-source:{ROOT}",
            "--policy",
            "format-summary",
            "--output",
            str(output),
            "--config-dir",
            str(config_dir),
            "--json",
        ],
    )

    assert result.exit_code == 2, result.output
    assert not output.exists()
    assert conflict.read_text(encoding="utf-8") == "existing artifact\n"
    assert not (tmp_path / "dataset.manifest.samplesheet.csv").exists()


def test_apply_overrides_bundle_conflict_does_not_leave_first_artifact(tmp_path: Path) -> None:
    manifest_path = tmp_path / "dataset.manifest.json"
    overrides_path = tmp_path / "dataset.overrides.json"
    output_dir = tmp_path / "resolved"
    write_model_atomic(_manifest(), manifest_path)
    write_model_atomic(
        ManifestOverrides(
            rename_samples={"Sensitive-A": "control_01"},
            reason="Synthetic reviewed rename.",
            approved_by="pytest-user",
        ),
        overrides_path,
    )
    output_dir.mkdir()
    conflict = output_dir / "reviewed.manifest.resolved.sanitized.json"
    conflict.write_text("existing artifact\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "manifest",
            "apply-overrides",
            str(manifest_path),
            "--overrides",
            str(overrides_path),
            "--output-dir",
            str(output_dir),
            "--name",
            "reviewed",
            "--json",
        ],
    )

    assert result.exit_code == 2, result.output
    assert not (output_dir / "reviewed.manifest.resolved.json").exists()
    assert conflict.read_text(encoding="utf-8") == "existing artifact\n"
    assert not (output_dir / "reviewed.override.applied.json").exists()
    assert not (output_dir / "reviewed.override.diff.json").exists()
    assert not (output_dir / "reviewed.samplesheet.csv").exists()
