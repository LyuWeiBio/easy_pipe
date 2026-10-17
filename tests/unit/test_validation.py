"""Static generated-project validation tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from biopipe.compiler import NextflowCompiler
from biopipe.manifests import finalize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    LaneFiles,
    ManifestPrivacy,
    ManifestSource,
)
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import load_default_registry
from biopipe.validation import FindingCode, validate_generated_project


def _manifest(*, layout: str = "paired_end", multilane: bool = True) -> DatasetManifest:
    root = "/srv/validation-fixture/raw"
    lanes = ("L001", "L002") if multilane else ("L001",)
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="fixture-source",
                root=root,
                scanned_at=datetime(2026, 7, 18, 3, 4, 5, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="illumina_fastq",
                layout=layout,  # type: ignore[arg-type]
                confidence=0.99,
            ),
            samples=[
                DatasetSample(
                    sample_id="sample-1",
                    lanes=[
                        LaneFiles(
                            lane=lane,
                            chunk="001",
                            read1=f"{root}/sample-1_{lane}_R1_001.fastq.gz",
                            read2=(
                                f"{root}/sample-1_{lane}_R2_001.fastq.gz"
                                if layout == "paired_end"
                                else None
                            ),
                        )
                        for lane in lanes
                    ],
                )
            ],
            observations=DatasetObservations(compression="gzip"),
            privacy=ManifestPrivacy(
                filenames_may_contain_identifiers=False,
                raw_content_exported=False,
            ),
        )
    )


def _generate(
    tmp_path: Path,
    *,
    layout: str = "paired_end",
    trimming: bool = True,
) -> tuple[Path, Path]:
    manifest = _manifest(layout=layout)
    output_target = tmp_path / "pipeline-results"
    planned = plan_fastq_qc(
        manifest,
        PlanningOptions(
            project_name="validation-project",
            trimming_enabled=trimming,
            minimum_length=35 if trimming else None,
            work_dir=str(tmp_path / "work"),
            output_dir=str(output_target),
            container_cache=str(tmp_path / "container-cache"),
            max_cpus=8,
            max_memory_gb=16,
        ),
    )
    project = tmp_path / "generated"
    NextflowCompiler().compile_planned(
        project,
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )
    return project, output_target


def _codes(project: Path) -> set[FindingCode]:
    return {finding.code for finding in validate_generated_project(project).findings}


def test_valid_project_has_deterministic_json_friendly_report(tmp_path: Path) -> None:
    project, output_target = _generate(tmp_path)

    first = validate_generated_project(project)
    second = validate_generated_project(project)

    assert first.status == "valid"
    assert first.findings == []
    assert first == second
    assert first.output_target_checked == str(output_target)
    assert "main.nf" in first.artifact_hashes
    assert json.loads(json.dumps(first.to_dict()))["status"] == "valid"


def test_validation_report_is_allowed_without_changing_project_validity(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path, layout="single_end", trimming=False)
    report = validate_generated_project(project)
    reports_directory = project / "reports"
    reports_directory.mkdir()
    (reports_directory / "validation.json").write_text(
        report.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )

    repeated = validate_generated_project(project)
    (reports_directory / "validation.json").write_text(
        repeated.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    repeated_again = validate_generated_project(project)

    assert repeated.status == "valid"
    assert repeated == repeated_again
    assert "reports/validation.json" not in repeated.checked_artifacts
    assert "reports/validation.json" not in repeated.artifact_hashes


def test_tampered_template_is_detected_by_content_and_audit_hash(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    main = project / "main.nf"
    main.write_text(main.read_text(encoding="utf-8") + "// tampered\n", encoding="utf-8")

    codes = _codes(project)

    assert FindingCode.GENERATED_CONTENT_MISMATCH in codes
    assert FindingCode.GENERATED_HASH_MISMATCH in codes


def test_tampered_license_is_detected_by_content_and_audit_hash(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    (project / "LICENSE").write_text("not the repository license\n", encoding="utf-8")

    codes = _codes(project)

    assert FindingCode.GENERATED_HASH_MISMATCH in codes


def test_tampered_lock_is_detected_against_exact_default_registry(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    lock_path = project / "software.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    lock["components"]["fastqc"]["digest"] = "sha256:" + "a" * 64
    lock_path.write_text(yaml.safe_dump(lock, sort_keys=True), encoding="utf-8")

    codes = _codes(project)

    assert FindingCode.SOFTWARE_LOCK_MISMATCH in codes
    assert FindingCode.GENERATED_HASH_MISMATCH in codes


def test_floating_non_digest_container_reference_is_detected(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    config_path = project / "conf/base.config"
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        config.replace(
            "quay.io/biocontainers/fastqc@sha256:"
            "e194048df39c3145d9b4e0a14f4da20b59d59250465b6f2a9cb698445fd45900",
            "quay.io/biocontainers/fastqc:latest",
            1,
        ),
        encoding="utf-8",
    )

    codes = _codes(project)

    assert FindingCode.CONTAINER_REFERENCE_INVALID in codes
    assert FindingCode.FLOATING_VERSION in codes


def test_tampered_samplesheet_is_detected_against_manifest_mapping(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    samplesheet = project / "assets/samplesheet.csv"
    samplesheet.write_text(
        samplesheet.read_text(encoding="utf-8").replace("sample-1,L001", "sample-x,L001"),
        encoding="utf-8",
    )

    codes = _codes(project)

    assert FindingCode.SAMPLESHEET_MISMATCH in codes
    assert FindingCode.GENERATED_HASH_MISMATCH in codes


def test_manifest_digest_tampering_is_detected(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    manifest_path = project / "dataset.manifest.resolved.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source"]["source_id"] = "changed-source"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    codes = _codes(project)

    assert FindingCode.MANIFEST_INTEGRITY_INVALID in codes


def test_path_policy_and_existing_output_conflicts_are_independent_findings(
    tmp_path: Path,
) -> None:
    project, output_target = _generate(tmp_path)
    spec_path = project / "pipeline.spec.yaml"
    plan_path = project / "execution.plan.yaml"
    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    spec["paths"]["work_dir"] = str(output_target)
    plan["paths"]["work_dir"] = str(output_target)
    spec["policy"]["network_access_during_tasks"] = True
    spec_path.write_text(yaml.safe_dump(spec, sort_keys=True), encoding="utf-8")
    plan_path.write_text(yaml.safe_dump(plan, sort_keys=True), encoding="utf-8")
    output_target.mkdir()

    codes = _codes(project)

    assert FindingCode.PATH_OVERLAP in codes
    assert FindingCode.DEFAULT_DENY_POLICY_INVALID in codes
    assert FindingCode.OUTPUT_CONFLICT in codes


def test_invalid_model_duplicate_keys_and_unsafe_symlink_fail_closed(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    spec_path = project / "pipeline.spec.yaml"
    spec_path.write_text(
        spec_path.read_text(encoding="utf-8") + "spec_version: '1.0'\n",
        encoding="utf-8",
    )
    (project / "unsafe-link").symlink_to(project / "main.nf")

    codes = _codes(project)

    assert FindingCode.ARTIFACT_MODEL_INVALID in codes
    assert FindingCode.UNSAFE_PROJECT_ENTRY in codes


def test_nonfinite_json_number_in_model_artifact_is_a_finding_not_a_crash(
    tmp_path: Path,
) -> None:
    project, _output_target = _generate(tmp_path)
    manifest_path = project / "dataset.manifest.resolved.json"
    text = manifest_path.read_text(encoding="utf-8")
    assert "0.99" in text
    manifest_path.write_text(text.replace("0.99", "Infinity", 1), encoding="utf-8")

    codes = _codes(project)  # must not raise

    assert FindingCode.ARTIFACT_MODEL_INVALID in codes


def test_nonfinite_json_number_in_audit_jsonl_is_a_finding_not_a_crash(
    tmp_path: Path,
) -> None:
    project, _output_target = _generate(tmp_path)
    audit_path = project / "audit" / "events.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text('{"event_type": Infinity}\n', encoding="utf-8")

    codes = _codes(project)  # must not raise

    assert FindingCode.AUDIT_RECORD_INVALID in codes


def test_missing_and_unexpected_generated_files_are_detected(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    (project / "modules/multiqc/main.nf").unlink()
    (project / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")

    report = validate_generated_project(project)
    file_set_findings = [
        finding
        for finding in report.findings
        if finding.code == FindingCode.GENERATED_FILE_SET_MISMATCH
    ]

    assert file_set_findings
    assert file_set_findings[0].context["missing"] == ["modules/multiqc/main.nf"]
    assert file_set_findings[0].context["unexpected"] == ["unexpected.txt"]


def test_missing_project_returns_report_instead_of_raising(tmp_path: Path) -> None:
    report = validate_generated_project(tmp_path / "missing")

    assert report.status == "invalid"
    assert [finding.code for finding in report.findings] == [FindingCode.PROJECT_NOT_FOUND]
    assert report.artifact_hashes == {}


def test_floating_version_detected_in_json_and_markdown_artifacts(
    tmp_path: Path,
) -> None:
    project, _output_target = _generate(tmp_path)
    (project / "extra.json").write_text('{"image": "tool:latest"}\n', encoding="utf-8")
    (project / "notes.md").write_text("# Notes\n\nUse image: latest for now.\n", encoding="utf-8")

    codes = _codes(project)

    assert FindingCode.FLOATING_VERSION in codes


def test_non_utf8_artifact_is_a_finding_not_silently_skipped(
    tmp_path: Path,
) -> None:
    project, _output_target = _generate(tmp_path)
    (project / "extra.json").write_bytes(b'{"image": "tool:\xff\xfe"}\n')

    findings = validate_generated_project(project).findings
    unreadable = {
        finding.artifact for finding in findings if finding.code == FindingCode.ARTIFACT_UNREADABLE
    }

    assert "extra.json" in unreadable


def test_validator_skips_path_data_artifacts_for_floating_versions(
    tmp_path: Path,
) -> None:
    project, _output_target = _generate(tmp_path)
    manifest_path = project / "dataset.manifest.resolved.json"
    text = manifest_path.read_text(encoding="utf-8")
    assert "/srv/validation-fixture/raw" in text
    manifest_path.write_text(
        text.replace("/srv/validation-fixture/raw", "/srv/my latest/raw"),
        encoding="utf-8",
    )

    codes = _codes(project)

    assert FindingCode.FLOATING_VERSION not in codes


def _read_generation_event(project: Path) -> dict:
    audit_path = project / "audit" / "events.jsonl"
    return json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])


def _write_generation_event(project: Path, event: dict) -> None:
    audit_path = project / "audit" / "events.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_audit_event_id_must_match_recomputed_fingerprint(tmp_path: Path) -> None:
    """P3 #3: a forged generation event_id is detected."""
    project, _output_target = _generate(tmp_path)
    assert _codes(project) == set()

    event = _read_generation_event(project)
    event["event_id"] = "00000000-0000-0000-0000-000000000000"
    _write_generation_event(project, event)

    assert FindingCode.AUDIT_RECORD_INVALID in _codes(project)


def test_audit_event_hash_tampering_breaks_event_id_binding(tmp_path: Path) -> None:
    """P3 #3: editing a claimed artifact hash invalidates the event_id binding."""
    project, _output_target = _generate(tmp_path)
    assert _codes(project) == set()

    event = _read_generation_event(project)
    first_output = sorted(event["output_hashes"])[0]
    event["output_hashes"][first_output] = "0" * 64
    _write_generation_event(project, event)

    assert FindingCode.AUDIT_RECORD_INVALID in _codes(project)


def _append_runtime_event(project: Path, event: dict) -> None:
    audit_path = project / "audit" / "events.jsonl"
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def _runtime_event(project: Path, generation_event: dict, **overrides: object) -> dict:
    base = {
        "schema_version": "1.0",
        "event_id": "11111111-2222-4333-8444-555555555555",
        "timestamp": generation_event["timestamp"],
        "event_type": "REAL_DATA_APPROVED",
        "project_id": generation_event["project_id"],
        "actor": "pytest-operator",
        "input_hashes": {
            "dataset_manifest": generation_event["input_hashes"][
                "dataset.manifest.resolved.json"
            ],
            "pipeline_spec": generation_event["input_hashes"]["pipeline.spec.yaml"],
            "execution_plan": generation_event["input_hashes"]["execution.plan.yaml"],
            "software_lock": generation_event["input_hashes"]["software.lock.yaml"],
        },
        "output_hashes": {},
        "status": "success",
        "summary": "synthetic runtime event",
    }
    base.update(overrides)
    return base


def test_runtime_event_with_matching_hashes_is_accepted(tmp_path: Path) -> None:
    project, _output_target = _generate(tmp_path)
    generation_event = _read_generation_event(project)
    _append_runtime_event(project, _runtime_event(project, generation_event))

    assert _codes(project) == set()


def test_runtime_event_with_divergent_artifact_hash_is_rejected(
    tmp_path: Path,
) -> None:
    """P3 #3: a runtime event referencing other artifacts is tampering."""
    project, _output_target = _generate(tmp_path)
    generation_event = _read_generation_event(project)
    tampered = _runtime_event(project, generation_event)
    tampered["input_hashes"]["dataset_manifest"] = "f" * 64
    _append_runtime_event(project, tampered)

    assert FindingCode.AUDIT_RECORD_INVALID in _codes(project)


def test_duplicate_runtime_event_id_is_rejected(tmp_path: Path) -> None:
    """P3 #3: duplicated event ids indicate log tampering."""
    project, _output_target = _generate(tmp_path)
    generation_event = _read_generation_event(project)
    first = _runtime_event(project, generation_event)
    second = _runtime_event(project, generation_event)
    second["event_id"] = first["event_id"]
    _append_runtime_event(project, first)
    _append_runtime_event(project, second)

    assert FindingCode.AUDIT_RECORD_INVALID in _codes(project)


def test_finding_text_covers_every_finding_code() -> None:
    """P3 #36: FindingCode and _FINDING_TEXT stay in lockstep."""
    from biopipe.validation.models import FindingCode
    from biopipe.validation.validator import _FINDING_TEXT

    assert set(_FINDING_TEXT) == set(FindingCode), (
        f"missing text: {set(FindingCode) - set(_FINDING_TEXT)}; "
        f"orphan text: {set(_FINDING_TEXT) - set(FindingCode)}"
    )
    for code, (message, remediation) in _FINDING_TEXT.items():
        assert message and message.strip(), f"{code} has an empty message"
        assert remediation, f"{code} has no remediation guidance"
