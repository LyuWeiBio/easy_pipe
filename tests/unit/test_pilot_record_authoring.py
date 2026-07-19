"""Behavior tests for blocked sanitized-pilot record authoring."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.pilot import (
    PILOT_SUMMARY_NAME,
    SanitizedPilotRecord,
    create_pilot_evidence,
)
from biopipe.release_evidence.pilot_record import (
    build_unexecuted_pilot_record,
    create_unexecuted_pilot_record,
    validate_sanitized_pilot_record,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SUPPORT = REPOSITORY_ROOT / "tests" / "pilot_evidence_support.py"


def _load_support() -> ModuleType:
    module_name = "_easy_pipe_pilot_evidence_test_support"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, SUPPORT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


support = _load_support()


def _arguments(root: Path) -> dict[str, Any]:
    root.mkdir(mode=0o700)
    repository = root / "repository"
    repository.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    return {
        "repository": repository,
        "output_file": private / "pilot-record.json",
        "pilot_id": "pilot-20260719-001",
        "environment_id": "env-001",
        "recorded_at": support.RECORDED_AT,
        "release_id": support.RELEASE_ID,
        "source_git_commit": support.COMMIT,
        "candidate_manifest_sha256": support.CANDIDATE_MANIFEST,
        "release_acceptance_manifest_sha256": support.ACCEPTANCE_MANIFEST,
        "real_host_manifest_sha256": support.REAL_HOST_MANIFEST,
    }


def test_initializer_is_deterministic_private_and_honestly_unexecuted(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    first = create_unexecuted_pilot_record(**arguments)
    first_path = Path(arguments["output_file"])
    second_path = first_path.with_name("pilot-record-second.json")
    second = create_unexecuted_pilot_record(**{**arguments, "output_file": second_path})

    assert first == second
    assert first.canonical_json is True
    assert first.record_state == "STRICT_FORMAT_VALIDATED_ONLY"
    assert first.source_evidence_authentication_status == "NOT_PERFORMED"
    assert first.independent_review_status == "NOT_PERFORMED"
    assert first.milestone_decision == "BLOCKED"
    assert first.production_authorization is False
    assert first.network_accessed is False
    assert first.project_tree_read is False
    assert first.private_state_read is False
    assert first.raw_content_exported is False
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_path.read_bytes().decode("ascii").endswith("\n")
    assert not first_path.read_bytes().decode("ascii").endswith("\n\n")
    assert stat.S_IMODE(first_path.stat(follow_symlinks=False).st_mode) == 0o600
    assert first_path.stat(follow_symlinks=False).st_nlink == 1

    record = SanitizedPilotRecord.model_validate(json.loads(first_path.read_text(encoding="ascii")))
    built = build_unexecuted_pilot_record(
        **{
            key: value
            for key, value in arguments.items()
            if key not in {"repository", "output_file"}
        }
    )
    assert record == built
    assert len(record.cases) == 6
    assert all(item.state == "unexecuted" for item in record.cases)
    assert all(item.data_classification == "synthetic" for item in record.cases)
    assert len(record.drills) == 10
    assert all(item.state == "unexecuted" for item in record.drills)
    assert all(item.observed_code == "NOT_OBSERVED" for item in record.drills)
    assert all(item.control_relaxed is False for item in record.drills)
    assert record.entry_gate.status == "not_recorded"
    assert all(item.status == "pending" for item in record.owner_assignments)
    assert record.capacity_retention.capacity_decision == "pending"
    assert record.capacity_retention.retention_decision == "pending"
    assert record.backup_restore.status == "not_run"
    assert record.operator_documentation.result == "not_observed"
    assert record.friction_review_status == "not_recorded"
    assert record.friction == []
    assert record.corrective_actions == []
    assert record.control_deviation.status == "none"
    assert record.controls_relaxed is False
    assert record.next_recommendation == "remain_blocked"


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("pilot_id", "pilot-private"),
        ("pilot_id", "pilot-20260718-001"),
        ("environment_id", "production-host"),
        ("recorded_at", "2026-07-19T08:00:00+00:00"),
        ("release_id", "0.1.0"),
        ("source_git_commit", "a" * 39),
        ("candidate_manifest_sha256", "A" * 64),
        ("release_acceptance_manifest_sha256", "c" * 63),
        ("real_host_manifest_sha256", "not-a-digest"),
    ],
)
def test_initializer_parameters_fail_closed_without_publication(
    tmp_path: Path,
    field: str,
    invalid: str,
) -> None:
    arguments = _arguments(tmp_path / "case")
    arguments[field] = invalid

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {
        "reason": "pilot_record_template_parameters"
    }
    assert not Path(arguments["output_file"]).exists()


def test_validate_accepts_noncanonical_order_without_modifying_input(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    canonical = create_unexecuted_pilot_record(**arguments)
    canonical_path = Path(arguments["output_file"])
    value = json.loads(canonical_path.read_text(encoding="ascii"))
    value["cases"] = list(reversed(value["cases"]))
    value["drills"] = list(reversed(value["drills"]))
    value["owner_assignments"] = list(reversed(value["owner_assignments"]))
    noncanonical_path = canonical_path.with_name("pilot-record-minified.json")
    noncanonical_path.write_text(
        json.dumps(value, ensure_ascii=True, separators=(",", ":")),
        encoding="ascii",
    )
    noncanonical_path.chmod(0o600)
    before = noncanonical_path.stat(follow_symlinks=False)
    payload = noncanonical_path.read_bytes()

    validated = validate_sanitized_pilot_record(
        repository=arguments["repository"],
        record_file=noncanonical_path,
    )

    after = noncanonical_path.stat(follow_symlinks=False)
    assert validated.canonical_json is False
    assert (
        validated.normalized_sanitized_record_sha256 == canonical.normalized_sanitized_record_sha256
    )
    assert noncanonical_path.read_bytes() == payload
    assert (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    )


def test_format_valid_ready_record_never_becomes_an_authorization(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    record_path = Path(arguments["output_file"])
    record_path.write_bytes(support.json_bytes(support.ready_record()))
    record_path.chmod(0o600)

    result = validate_sanitized_pilot_record(
        repository=arguments["repository"],
        record_file=record_path,
    )

    assert result.record_state == "STRICT_FORMAT_VALIDATED_ONLY"
    assert result.source_evidence_authentication_status == "NOT_PERFORMED"
    assert result.independent_review_status == "NOT_PERFORMED"
    assert result.milestone_decision == "BLOCKED"
    assert result.production_authorization is False


def test_initializer_is_create_only_and_preserves_existing_destination(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    output = Path(arguments["output_file"])
    marker = b"operator-owned-existing-record\n"
    output.write_bytes(marker)
    output.chmod(0o600)

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert output.read_bytes() == marker
    assert not list(output.parent.glob(".*.biopipe-*"))


def test_initializer_forces_private_mode_even_under_restrictive_umask(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    previous = os.umask(0o777)
    try:
        create_unexecuted_pilot_record(**arguments)
    finally:
        os.umask(previous)

    output = Path(arguments["output_file"])
    assert stat.S_IMODE(output.stat(follow_symlinks=False).st_mode) == 0o600


def test_initialized_record_uses_the_compiler_normalization_and_stays_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    support.patch_external_bindings(monkeypatch)
    compiler_arguments = support.create_arguments(tmp_path / "case", support.incomplete_record())
    initialized = Path(compiler_arguments["sanitized_record"]).with_name("initialized-record.json")
    init_arguments = _arguments(tmp_path / "authoring")
    init_arguments["output_file"] = initialized
    validation = create_unexecuted_pilot_record(**init_arguments)
    compiler_arguments["sanitized_record"] = initialized

    compiled = create_pilot_evidence(**compiler_arguments)

    assert compiled.criteria_state == "INCOMPLETE_OR_BLOCKED"
    assert compiled.milestone_decision == "BLOCKED"
    output = Path(compiler_arguments["output_directory"])
    summary = json.loads((output / PILOT_SUMMARY_NAME).read_text(encoding="ascii"))
    assert (
        summary["evidence_bindings"]["normalized_sanitized_record_sha256"]
        == validation.normalized_sanitized_record_sha256
    )
