"""Manifest integrity, privacy, override, samplesheet, and storage tests."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from biopipe.detectors import FastqFileFacts, MateMarkerCounts, detect_fastq_dataset
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model
from biopipe.manifests import (
    ManifestArtifactStore,
    apply_overrides,
    build_manifest,
    finalize_manifest,
    render_samplesheet,
    sanitize_manifest,
    verify_manifest,
)
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    DetectionEvidence,
    LaneFiles,
    ManifestIssue,
    ManifestOverrides,
    ManifestPrivacy,
    ManifestSource,
    ReadLengthSummary,
)

ROOT = "/srv/synthetic raw"


def _manifest(*, with_error: bool = False) -> DatasetManifest:
    manifest = DatasetManifest(
        source=ManifestSource(
            source_id="private-source",
            root=ROOT,
            scanned_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            scan_policy="format_summary",
        ),
        classification=DatasetClassification(
            dataset_type="illumina_fastq",
            layout="paired_end",
            confidence=0.97,
        ),
        samples=[
            DatasetSample(
                sample_id="internal-a",
                original_sample_name="Patient-A",
                lanes=[
                    LaneFiles(
                        lane="L001",
                        chunk="001",
                        read1=f"{ROOT}/Patient-A_L001_R1_001.fastq.gz",
                        read2=f"{ROOT}/Patient-A_L001_R2_001.fastq.gz",
                    ),
                    LaneFiles(
                        lane="L002",
                        chunk="001",
                        read1=f"{ROOT}/Patient-A_L002_R1_001.fastq.gz",
                        read2=f"{ROOT}/Patient-A_L002_R2_001.fastq.gz",
                    ),
                ],
            ),
            DatasetSample(
                sample_id="internal-b",
                original_sample_name="Patient-B",
                lanes=[
                    LaneFiles(
                        lane="L001",
                        chunk="001",
                        read1=f"{ROOT}/Patient-B_L001_R1_001.fastq.gz",
                        read2=f"{ROOT}/Patient-B_L001_R2_001.fastq.gz",
                    )
                ],
            ),
        ],
        observations=DatasetObservations(
            compression="gzip",
            read_length=ReadLengthSummary(minimum=150, median=150.0, maximum=150),
            likely_quality_encoding="phred33",
            header_family="illumina_casava_1_8",
        ),
        evidence=[
            DetectionEvidence(
                rule="valid_fastq_structure",
                score=0.25,
                detail=f"Observed Patient-A below {ROOT}",
            )
        ],
        warnings=[
            ManifestIssue(
                code="SENSITIVE_FILENAME",
                severity="warning",
                message="Patient-A may identify a subject.",
                context={"path": f"{ROOT}/Patient-A_L001_R1_001.fastq.gz"},
            )
        ],
        errors=(
            [
                ManifestIssue(
                    code="PAIRING_BLOCKED",
                    severity="blocking",
                    message="Synthetic blocking error.",
                )
            ]
            if with_error
            else []
        ),
        privacy=ManifestPrivacy(
            filenames_may_contain_identifiers=True,
            raw_content_exported=False,
        ),
    )
    return finalize_manifest(manifest)


def test_manifest_digest_is_deterministic_and_detects_mutation() -> None:
    first = _manifest()
    second = finalize_manifest(first)

    assert first.integrity.manifest_sha256 == second.integrity.manifest_sha256
    assert verify_manifest(first)
    changed = first.model_copy(deep=True)
    changed.classification.confidence = 0.5
    assert not verify_manifest(changed)


def test_manifest_rejects_unsafe_or_ambiguous_file_assignments() -> None:
    base = _manifest().model_dump(mode="json")
    variants: list[dict[str, object]] = []

    outside = deepcopy(base)
    outside["samples"][0]["lanes"][0]["read1"] = "/etc/passwd"  # type: ignore[index]
    variants.append(outside)

    duplicate_path = deepcopy(base)
    duplicate_path["samples"][1]["lanes"][0]["read1"] = (  # type: ignore[index]
        duplicate_path["samples"][0]["lanes"][0]["read1"]  # type: ignore[index]
    )
    variants.append(duplicate_path)

    duplicate_sample = deepcopy(base)
    duplicate_sample["samples"][1]["sample_id"] = duplicate_sample["samples"][0][  # type: ignore[index]
        "sample_id"
    ]
    variants.append(duplicate_sample)

    duplicate_slot = deepcopy(base)
    duplicate_slot["samples"][0]["lanes"][1]["lane"] = "L001"  # type: ignore[index]
    variants.append(duplicate_slot)

    empty_paired = deepcopy(base)
    empty_paired["samples"] = []
    empty_paired["classification"]["layout"] = "paired_end"  # type: ignore[index]
    variants.append(empty_paired)

    unresolved_without_error = deepcopy(base)
    unresolved_without_error["classification"]["layout"] = "unknown"  # type: ignore[index]
    variants.append(unresolved_without_error)

    empty_without_error = deepcopy(base)
    empty_without_error["samples"] = []
    empty_without_error["classification"]["layout"] = "unknown"  # type: ignore[index]
    variants.append(empty_without_error)

    mixed_without_error = deepcopy(base)
    mixed_without_error["samples"][0]["lanes"][0]["read2"] = None  # type: ignore[index]
    mixed_without_error["classification"]["layout"] = "unknown"  # type: ignore[index]
    variants.append(mixed_without_error)

    for payload in variants:
        with pytest.raises(ValidationError):
            DatasetManifest.model_validate(payload)


def test_sanitized_manifest_removes_names_paths_and_free_text() -> None:
    sanitized = sanitize_manifest(_manifest())
    payload = sanitized.model_dump_json()

    assert verify_manifest(sanitized)
    for sensitive in (
        "Patient-A",
        "Patient-B",
        "private-source",
        ROOT,
        "internal-a",
        "internal-b",
    ):
        assert sensitive not in payload
    assert [sample.sample_id for sample in sanitized.samples] == ["sample_001", "sample_002"]
    assert all(sample.original_sample_name is None for sample in sanitized.samples)
    assert sanitized.source.root == "/redacted"
    assert sanitized.privacy.artifact_scope == "sanitized"
    assert sanitized.privacy.filenames_may_contain_identifiers is False
    assert {lane.lane for sample in sanitized.samples for lane in sample.lanes} <= {
        "lane_001",
        "lane_002",
    }


def test_sanitizer_allowlists_codes_rules_and_header_families() -> None:
    crafted = _manifest().model_copy(deep=True)
    crafted.observations.header_family = "PatientSecret"
    crafted.evidence = [DetectionEvidence(rule="PatientSecret", score=0.5, detail="PatientSecret")]
    crafted.warnings = [
        ManifestIssue(
            code="PatientSecret",
            severity="warning",
            message="PatientSecret",
            context={"PatientSecret": "PatientSecret"},
            remediation=["PatientSecret"],
        )
    ]
    crafted = finalize_manifest(crafted)

    sanitized = sanitize_manifest(crafted)
    payload = sanitized.model_dump_json()

    assert "PatientSecret" not in payload
    assert sanitized.observations.header_family == "unknown"
    assert sanitized.evidence[0].rule == "redacted_evidence"
    assert sanitized.warnings[0].code == "redacted_issue"


def test_sanitizer_preserves_generated_no_fastq_error_code() -> None:
    original = _manifest()
    excluded = [
        path
        for sample in original.samples
        for lane in sample.lanes
        for path in (lane.read1, lane.read2)
        if path is not None
    ]
    resolved = apply_overrides(
        original,
        ManifestOverrides(
            exclude_files=excluded,
            reason="All synthetic inputs were excluded.",
            approved_by="pytest",
        ),
    ).resolved_manifest

    assert [issue.code for issue in resolved.errors] == ["no_fastq_files"]
    sanitized = sanitize_manifest(resolved)
    assert [issue.code for issue in sanitized.errors] == ["no_fastq_files"]


def test_samplesheet_is_stable_and_refuses_blocking_manifest() -> None:
    samplesheet = render_samplesheet(_manifest())

    assert samplesheet.splitlines()[0] == "sample_id,lane,chunk,read1,read2"
    assert samplesheet.count("\n") == 4
    assert samplesheet.index("internal-a") < samplesheet.index("internal-b")
    with pytest.raises(BioPipeError) as captured:
        render_samplesheet(_manifest(with_error=True))
    assert captured.value.code == ErrorCode.VALIDATION_FAILED


def test_overrides_are_traceable_and_do_not_mutate_original() -> None:
    original = _manifest()
    original_json = original.model_dump_json()
    overrides = ManifestOverrides(
        rename_samples={"Patient-A": "control_01"},
        exclude_files=[
            f"{ROOT}/Patient-A_L002_R1_001.fastq.gz",
            f"{ROOT}/Patient-A_L002_R2_001.fastq.gz",
        ],
        manual_pairs=[
            {
                "sample_id": "special_01",
                "lane": "L001",
                "read1": f"{ROOT}/Patient-B_L001_R1_001.fastq.gz",
                "read2": f"{ROOT}/Patient-B_L001_R2_001.fastq.gz",
            }
        ],
        reason="Reviewed synthetic delivery metadata.",
        approved_by="pytest-user",
    )

    application = apply_overrides(original, overrides)
    resolved = application.resolved_manifest

    assert original.model_dump_json() == original_json
    assert verify_manifest(resolved)
    assert [sample.sample_id for sample in resolved.samples] == [
        "control_01",
        "special_01",
    ]
    assert len(resolved.samples[0].lanes) == 1
    assert resolved.classification.layout == "paired_end"
    assert application.diff.original_manifest_sha256 == original.integrity.manifest_sha256
    assert application.diff.resolved_manifest_sha256 == resolved.integrity.manifest_sha256
    assert application.diff.manual_pair_count == 1
    assert len(application.diff.override_sha256) == 64


def test_empty_override_preserves_unresolved_pairing_error() -> None:
    read1 = f"{ROOT}/orphan_R1.fastq.gz"
    original = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="private-source",
                root=ROOT,
                scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="generic_fastq",
                layout="unknown",
                confidence=0.8,
            ),
            samples=[
                DatasetSample(
                    sample_id="sample_001",
                    original_sample_name="orphan",
                    lanes=[LaneFiles(read1=read1)],
                )
            ],
            errors=[
                ManifestIssue(
                    code="missing_mate",
                    severity="blocking",
                    message="Missing read 2.",
                    context={"sample_key": "orphan", "paths": [read1]},
                )
            ],
        )
    )

    resolved = apply_overrides(
        original,
        ManifestOverrides(reason="Reviewed only.", approved_by="pytest"),
    ).resolved_manifest

    assert [issue.code for issue in resolved.errors] == ["missing_mate"]
    assert resolved.classification.layout == "unknown"


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        (
            "duplicate.json",
            '{"reason":"first","reason":"second","approved_by":"pytest"}',
        ),
        (
            "duplicate.yaml",
            "reason: reviewed\napproved_by: first\napproved_by: second\n",
        ),
    ],
)
def test_override_inputs_reject_duplicate_json_and_yaml_keys(
    tmp_path: Path,
    name: str,
    payload: str,
) -> None:
    path = tmp_path / name
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(BioPipeError) as captured:
        read_model(path, ManifestOverrides)

    assert captured.value.code is ErrorCode.ARTIFACT_READ_FAILED


def test_manual_pair_can_reassign_scanned_orphan_paths() -> None:
    read1 = f"{ROOT}/orphan_R1.fastq.gz"
    read2 = f"{ROOT}/orphan_R2.fastq.gz"
    original = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="private-source",
                root=ROOT,
                scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="generic_fastq",
                layout="unknown",
                confidence=0.8,
            ),
            samples=[
                DatasetSample(
                    sample_id="sample_001",
                    original_sample_name="orphan",
                    lanes=[LaneFiles(read1=read1)],
                )
            ],
            errors=[
                ManifestIssue(
                    code="missing_mate",
                    severity="blocking",
                    message="Pairing was unresolved.",
                    context={"sample_key": "orphan", "paths": [read1, read2]},
                )
            ],
        )
    )
    overrides = ManifestOverrides(
        manual_pairs=[{"sample_id": "resolved", "read1": read1, "read2": read2}],
        reason="Both scanned candidates were reviewed.",
        approved_by="pytest",
    )

    resolved = apply_overrides(original, overrides).resolved_manifest

    assert not resolved.errors
    assert resolved.classification.layout == "paired_end"
    assert resolved.samples[0].sample_id == "resolved"


def test_empty_override_is_idempotent_for_empty_dataset_errors() -> None:
    original = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="private-source",
                root=ROOT,
                scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="unknown",
                layout="unknown",
                confidence=0.0,
            ),
            errors=[
                ManifestIssue(
                    code="no_fastq_files",
                    severity="blocking",
                    message="No FASTQ files were detected.",
                )
            ],
        )
    )
    overrides = ManifestOverrides(reason="Reviewed only.", approved_by="pytest")

    first = apply_overrides(original, overrides).resolved_manifest
    second = apply_overrides(first, overrides).resolved_manifest

    assert [issue.code for issue in first.errors] == ["no_fastq_files"]
    assert second.model_dump(mode="json") == first.model_dump(mode="json")


def test_empty_override_preserves_r2_only_missing_mate_manifest() -> None:
    detection = detect_fastq_dataset([_detector_fact(f"{ROOT}/orphan_R2.fastq.gz", "read2")])
    original = build_manifest(
        source_id="private-source",
        root=ROOT,
        scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        detection=detection,
    )
    assert not original.samples
    assert [issue.code for issue in original.errors] == ["missing_mate"]

    application = apply_overrides(
        original,
        ManifestOverrides(reason="Reviewed only.", approved_by="pytest"),
    )

    assert application.resolved_manifest.model_dump(mode="json") == original.model_dump(mode="json")
    assert application.diff.resolved_manifest_sha256 == application.diff.original_manifest_sha256


def test_empty_override_does_not_duplicate_mixed_layout_error() -> None:
    original = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="private-source",
                root=ROOT,
                scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="generic_fastq",
                layout="unknown",
                confidence=0.8,
            ),
            samples=[
                DatasetSample(
                    sample_id="paired",
                    lanes=[
                        LaneFiles(
                            read1=f"{ROOT}/paired_R1.fastq",
                            read2=f"{ROOT}/paired_R2.fastq",
                        )
                    ],
                ),
                DatasetSample(
                    sample_id="single",
                    lanes=[LaneFiles(read1=f"{ROOT}/single.fastq")],
                ),
            ],
            errors=[
                ManifestIssue(
                    code="mixed_layout",
                    severity="blocking",
                    message="Mixed layouts require review.",
                )
            ],
        )
    )

    resolved = apply_overrides(
        original,
        ManifestOverrides(reason="Reviewed only.", approved_by="pytest"),
    ).resolved_manifest

    assert [issue.code for issue in resolved.errors] == ["mixed_layout"]

    repaired = apply_overrides(
        original,
        ManifestOverrides(
            exclude_files=[f"{ROOT}/single.fastq"],
            reason="The single-end delivery was excluded.",
            approved_by="pytest",
        ),
    ).resolved_manifest
    assert not repaired.errors
    assert repaired.classification.layout == "paired_end"


def test_sample_level_naming_conflict_paths_are_preserved_and_repairable() -> None:
    conflict_read1 = f"{ROOT}/conflict_R1.fastq"
    conflict_read2 = f"{ROOT}/conflict.2.fastq"
    detection = detect_fastq_dataset(
        [
            _detector_fact(conflict_read1, "read1"),
            _detector_fact(conflict_read2, "read2"),
            _detector_fact(f"{ROOT}/good_R1.fastq", "read1"),
            _detector_fact(f"{ROOT}/good_R2.fastq", "read2"),
        ]
    )
    original = build_manifest(
        source_id="private-source",
        root=ROOT,
        scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        detection=detection,
    )
    naming_error = next(issue for issue in original.errors if issue.code == "naming_conflict")
    assert naming_error.context["paths"] == [conflict_read1, conflict_read2]

    unresolved = apply_overrides(
        original,
        ManifestOverrides(reason="Reviewed only.", approved_by="pytest"),
    ).resolved_manifest
    assert "naming_conflict" in {issue.code for issue in unresolved.errors}

    repaired = apply_overrides(
        original,
        ManifestOverrides(
            manual_pairs=[
                {
                    "sample_id": "repaired",
                    "read1": conflict_read1,
                    "read2": conflict_read2,
                }
            ],
            reason="Both conflicting names were reviewed as one pair.",
            approved_by="pytest",
        ),
    ).resolved_manifest
    assert not repaired.errors
    assert repaired.classification.layout == "paired_end"


def test_valid_counterpart_of_invalid_mate_remains_a_scanned_override_fact() -> None:
    read1 = f"{ROOT}/damaged_R1.fastq"
    read2 = f"{ROOT}/damaged_R2.fastq"
    detection = detect_fastq_dataset(
        [
            _detector_fact(read1, "read1"),
            _detector_fact(read2, "read2", valid=False),
        ]
    )
    original = build_manifest(
        source_id="private-source",
        root=ROOT,
        scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        detection=detection,
    )
    invalid = next(issue for issue in original.errors if issue.code == "invalid_fastq_structure")
    assert invalid.context["related_paths"] == [read1, read2]

    repaired = apply_overrides(
        original,
        ManifestOverrides(
            exclude_files=[read2],
            manual_pairs=[{"sample_id": "recovered", "read1": read1}],
            reason="The invalid mate was excluded after review.",
            approved_by="pytest",
        ),
    ).resolved_manifest

    assert not repaired.errors
    assert repaired.classification.layout == "single_end"
    assert repaired.samples[0].lanes[0].read1 == read1


def _detector_fact(path: str, marker: str, *, valid: bool = True) -> FastqFileFacts:
    counts = {
        "read1": MateMarkerCounts(read_1=1, read_2=0, unknown=0, mixed=False),
        "read2": MateMarkerCounts(read_1=0, read_2=1, unknown=0, mixed=False),
    }
    return FastqFileFacts(
        path=path,
        compression="none",
        structure_valid=valid,
        read_length=(ReadLengthSummary(minimum=4, median=4.0, maximum=4) if valid else None),
        likely_quality_encoding="phred33" if valid else "unknown",
        header_family="generic" if valid else "unknown",
        mate_markers=counts[marker],
    )


@pytest.mark.parametrize(
    "overrides",
    [
        ManifestOverrides(
            rename_samples={"missing": "new_name"},
            reason="synthetic",
            approved_by="pytest",
        ),
        ManifestOverrides(
            exclude_files=[f"{ROOT}/Patient-A_L001_R1_001.fastq.gz"],
            reason="synthetic",
            approved_by="pytest",
        ),
        ManifestOverrides(
            manual_pairs=[
                {
                    "sample_id": "outside",
                    "read1": "/etc/outside.fastq",
                }
            ],
            reason="synthetic",
            approved_by="pytest",
        ),
        ManifestOverrides(
            manual_pairs=[
                {
                    "sample_id": "reuse",
                    "read1": f"{ROOT}/Patient-B_L001_R1_001.fastq.gz",
                    "read2": f"{ROOT}/new.fastq.gz",
                }
            ],
            reason="synthetic",
            approved_by="pytest",
        ),
        ManifestOverrides(
            manual_pairs=[
                {
                    "sample_id": "split_r1",
                    "read1": f"{ROOT}/Patient-B_L001_R1_001.fastq.gz",
                },
                {
                    "sample_id": "split_r2",
                    "read1": f"{ROOT}/Patient-B_L001_R2_001.fastq.gz",
                },
            ],
            reason="synthetic",
            approved_by="pytest",
        ),
    ],
)
def test_override_conflicts_fail_closed(overrides: ManifestOverrides) -> None:
    with pytest.raises(BioPipeError) as captured:
        apply_overrides(_manifest(), overrides)
    assert captured.value.code == ErrorCode.MANIFEST_OVERRIDE_CONFLICT


def test_manifest_store_is_create_only_and_rejects_symlink_reads(tmp_path: Path) -> None:
    store = ManifestArtifactStore(tmp_path / "manifests")
    manifest = _manifest()

    path = store.create_model("dataset.manifest.json", manifest)
    assert store.read_manifest(path.name) == manifest
    with pytest.raises(BioPipeError) as duplicate:
        store.create_model(path.name, manifest)
    assert duplicate.value.code == ErrorCode.MANIFEST_STORAGE_FAILED

    linked = store.directory / "linked.manifest.json"
    linked.symlink_to(path)
    with pytest.raises(BioPipeError):
        store.read_manifest(linked.name)

    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["integrity"]["manifest_sha256"] == manifest.integrity.manifest_sha256


def test_manifest_store_preflights_complete_bundle_before_creating_first(
    tmp_path: Path,
) -> None:
    store = ManifestArtifactStore(tmp_path / "manifests")
    store.directory.mkdir(parents=True)
    conflict = store.directory / "second.json"
    conflict.write_text("existing artifact\n", encoding="utf-8")

    with pytest.raises(BioPipeError) as captured:
        store.create_bundle(
            {
                "first.json": "new first artifact\n",
                "second.json": "must not replace existing\n",
            }
        )

    assert captured.value.code == ErrorCode.MANIFEST_STORAGE_FAILED
    assert not (store.directory / "first.json").exists()
    assert conflict.read_text(encoding="utf-8") == "existing artifact\n"


def test_manifest_store_rolls_back_own_links_after_late_create_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ManifestArtifactStore(tmp_path / "manifests")
    original_link = os.link

    def race_on_second(source: str | bytes | Path, destination: str | bytes | Path) -> None:
        if Path(destination).name == "second.json":
            raise FileExistsError(17, "synthetic create race", destination)
        original_link(source, destination)

    monkeypatch.setattr("biopipe.manifests.store.os.link", race_on_second)

    with pytest.raises(BioPipeError) as captured:
        store.create_bundle(
            {
                "first.json": "new first artifact\n",
                "second.json": "new second artifact\n",
            }
        )

    assert captured.value.code == ErrorCode.MANIFEST_STORAGE_FAILED
    assert not (store.directory / "first.json").exists()
    assert not (store.directory / "second.json").exists()
    assert list(store.directory.iterdir()) == []
