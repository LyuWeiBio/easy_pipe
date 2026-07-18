"""End-to-end CLI acceptance tests for M3 planning and generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml
from typer.testing import CliRunner

from biopipe.cli.app import app
from biopipe.io import write_model_atomic
from biopipe.manifests import finalize_manifest, sanitize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetSample,
    LaneFiles,
    ManifestSource,
)

runner = CliRunner()
RAW_ROOT = "/srv/m3-synthetic-raw"


def _manifest(*, paired: bool, multilane: bool = False) -> DatasetManifest:
    lanes = [
        LaneFiles(
            lane="L001",
            read1=f"{RAW_ROOT}/sample_A_L001_R1.fastq.gz",
            read2=f"{RAW_ROOT}/sample_A_L001_R2.fastq.gz" if paired else None,
        )
    ]
    if multilane:
        lanes.append(
            LaneFiles(
                lane="L002",
                read1=f"{RAW_ROOT}/sample_A_L002_R1.fastq.gz",
                read2=f"{RAW_ROOT}/sample_A_L002_R2.fastq.gz" if paired else None,
            )
        )
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="m3-source",
                root=RAW_ROOT,
                scanned_at=datetime(2026, 7, 18, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="illumina_fastq",
                layout="paired_end" if paired else "single_end",
                confidence=1.0,
            ),
            samples=[
                DatasetSample(
                    sample_id="sample_A",
                    original_sample_name="participant-A",
                    lanes=lanes,
                )
            ],
        )
    )


def _plan(tmp_path: Path, *, paired: bool = False, trimming: bool = False) -> Path:
    manifest_path = tmp_path / "input.manifest.json"
    spec_path = tmp_path / "plan" / "pipeline.spec.yaml"
    write_model_atomic(_manifest(paired=paired, multilane=paired), manifest_path)
    arguments = [
        "plan",
        "--manifest",
        str(manifest_path),
        "--goal",
        "fastq-qc",
        "--output",
        str(spec_path),
        "--json",
    ]
    if trimming:
        arguments.extend(["--trimming", "--minimum-length", "28"])
    result = runner.invoke(app, arguments)
    assert result.exit_code == 0, result.output
    response = json.loads(result.stdout)
    assert response["status"] == "planned"
    return spec_path


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_plan_and_generate_single_end_project_deterministically(tmp_path: Path) -> None:
    spec_path = _plan(tmp_path)
    plan_dir = spec_path.parent
    assert (plan_dir / "dataset.manifest.resolved.json").is_file()
    assert (plan_dir / "execution.plan.yaml").is_file()
    assert (plan_dir / "software.lock.yaml").is_file()

    first = tmp_path / "generated-a"
    second = tmp_path / "generated-b"
    results = [
        runner.invoke(
            app,
            ["generate", "--spec", str(spec_path), "--output", str(output), "--json"],
        )
        for output in (first, second)
    ]
    assert all(result.exit_code == 0 for result in results), [result.output for result in results]
    assert (
        json.loads(results[0].stdout)["generation_fingerprint"]
        == json.loads(results[1].stdout)["generation_fingerprint"]
    )
    assert _tree_bytes(first) == _tree_bytes(second)
    assert (first / "main.nf").is_file()
    assert (first / "modules/fastqc/raw.nf").is_file()
    assert not (first / "modules/fastp/main.nf").exists()
    assert b"latest" not in b"\n".join(_tree_bytes(first).values()).lower()


def test_generate_paired_multilane_project_with_trimming(tmp_path: Path) -> None:
    spec_path = _plan(tmp_path, paired=True, trimming=True)
    output = tmp_path / "generated"

    result = runner.invoke(
        app,
        ["generate", "--spec", str(spec_path), "--output", str(output), "--json"],
    )

    assert result.exit_code == 0, result.output
    samplesheet = (output / "assets/samplesheet.csv").read_text(encoding="utf-8")
    assert sum(line.startswith("sample_A,") for line in samplesheet.splitlines()) == 2
    assert "sample_A_L001_R2.fastq.gz" in samplesheet
    assert "sample_A_L002_R2.fastq.gz" in samplesheet
    assert (output / "modules/fastp/main.nf").is_file()
    assert (output / "modules/fastqc/post_trim.nf").is_file()
    assert "--length_required 28" in (output / "modules/fastp/main.nf").read_text(encoding="utf-8")


def test_plan_bundle_conflict_is_all_or_nothing(tmp_path: Path) -> None:
    manifest_path = tmp_path / "input.manifest.json"
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    write_model_atomic(_manifest(paired=False), manifest_path)
    conflict = plan_dir / "software.lock.yaml"
    conflict.write_text("keep-me\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "plan",
            "--manifest",
            str(manifest_path),
            "--output",
            str(plan_dir / "pipeline.spec.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2, result.output
    assert conflict.read_text(encoding="utf-8") == "keep-me\n"
    assert not (plan_dir / "pipeline.spec.yaml").exists()
    assert not (plan_dir / "execution.plan.yaml").exists()
    assert not (plan_dir / "dataset.manifest.resolved.json").exists()


def test_generate_rejects_tampered_lock_and_preserves_output(tmp_path: Path) -> None:
    spec_path = _plan(tmp_path)
    lock_path = spec_path.parent / "software.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    lock["components"]["fastqc"]["version"] = "0.0.0"
    lock_path.write_text(yaml.safe_dump(lock, sort_keys=True), encoding="utf-8")
    output = tmp_path / "generated"
    output.mkdir()
    sentinel = output / "sentinel.txt"
    sentinel.write_text("unchanged\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["generate", "--spec", str(spec_path), "--output", str(output), "--json"],
    )

    assert result.exit_code == 2, result.output
    assert "VALIDATION_FAILED" in result.output
    assert sentinel.read_text(encoding="utf-8") == "unchanged\n"
    assert list(output.iterdir()) == [sentinel]


def test_plan_rejects_sanitized_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "sanitized.json"
    write_model_atomic(sanitize_manifest(_manifest(paired=False)), manifest_path)

    result = runner.invoke(
        app,
        [
            "plan",
            "--manifest",
            str(manifest_path),
            "--output",
            str(tmp_path / "plan" / "pipeline.spec.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2, result.output
    assert "Sanitized manifests" in result.output
    assert not (tmp_path / "plan").exists()
