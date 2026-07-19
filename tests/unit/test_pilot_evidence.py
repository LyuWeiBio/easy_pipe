"""Focused behavior tests for privacy-safe internal-pilot evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

import biopipe.release_evidence.pilot as pilot
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.pilot import (
    PILOT_EVIDENCE_NAMES,
    PILOT_REPORT_NAME,
    PILOT_SUMMARY_NAME,
    create_pilot_evidence,
    verify_pilot_evidence,
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
COMMIT = support.COMMIT
PRIVATE_SENTINEL = support.PRIVATE_SENTINEL
bundle_bytes = support.bundle_bytes
create_arguments = support.create_arguments
incomplete_record = support.incomplete_record
patch_external_bindings = support.patch_external_bindings
ready_record = support.ready_record


def test_create_and_offline_verify_honest_incomplete_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())

    created = create_pilot_evidence(**arguments)
    output = arguments["output_directory"]
    assert isinstance(output, Path)
    assert frozenset(path.name for path in output.iterdir()) == PILOT_EVIDENCE_NAMES
    assert created == verify_pilot_evidence(output)
    assert created.criteria_state == "INCOMPLETE_OR_BLOCKED"
    assert created.milestone_decision == "BLOCKED"
    assert created.independent_review_status == "PENDING_INDEPENDENT_REVIEW"
    assert created.source_git_commit == COMMIT

    summary = json.loads((output / PILOT_SUMMARY_NAME).read_text(encoding="ascii"))
    assert summary["record_state"] == "OPERATOR_RECORDED_UNREVIEWED"
    assert summary["production_authorization"] is False
    assert summary["project_tree_read"] is False
    assert summary["private_state_read"] is False
    assert summary["network_accessed"] is False
    assert summary["criteria"]["recorded_successful_case_count"] == 0
    assert summary["criteria"]["recorded_recovered_drill_count"] == 0
    report = (output / PILOT_REPORT_NAME).read_text(encoding="ascii")
    assert "DRAFT" not in report  # the exact state banner is operator-recorded unreviewed
    assert "OPERATOR_RECORDED_UNREVIEWED" in report
    assert "M6.2 decision: `BLOCKED`" in report
    assert PRIVATE_SENTINEL not in bundle_bytes(output).decode("ascii")


def test_recorded_criteria_can_be_ready_for_review_but_never_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", ready_record())

    result = create_pilot_evidence(**arguments)

    assert result.criteria_state == "READY_FOR_INDEPENDENT_REVIEW"
    assert result.milestone_decision == "BLOCKED"
    output = arguments["output_directory"]
    assert isinstance(output, Path)
    summary = json.loads((output / PILOT_SUMMARY_NAME).read_text(encoding="ascii"))
    assert summary["criteria"]["recorded_successful_case_count"] == 3
    assert summary["criteria"]["recorded_recovered_drill_count"] == 3
    assert summary["independent_review_status"] == "PENDING_INDEPENDENT_REVIEW"
    assert summary["production_authorization"] is False


def test_pending_m61_entry_gate_cannot_reach_review_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    record["entry_gate"]["status"] = "recorded_pending_independent_review"
    arguments = create_arguments(tmp_path / "case", record)

    result = create_pilot_evidence(**arguments)

    assert result.criteria_state == "INCOMPLETE_OR_BLOCKED"
    output = Path(arguments["output_directory"])
    summary = json.loads((output / PILOT_SUMMARY_NAME).read_text(encoding="ascii"))
    assert summary["criteria"]["entry_gate_recorded_complete"] is False


def test_unrecorded_friction_review_cannot_be_treated_as_no_friction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    record["friction_review_status"] = "not_recorded"
    arguments = create_arguments(tmp_path / "case", record)

    result = create_pilot_evidence(**arguments)

    assert result.criteria_state == "INCOMPLETE_OR_BLOCKED"
    output = Path(arguments["output_directory"])
    summary = json.loads((output / PILOT_SUMMARY_NAME).read_text(encoding="ascii"))
    assert summary["criteria"]["friction_review_recorded"] is False


def test_duplicate_recorded_run_identity_cannot_imply_independence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    record["cases"][1]["hashes"] = record["cases"][0]["hashes"]
    record["cases"][1]["run_id_sha256"] = record["cases"][0]["run_id_sha256"]
    arguments = create_arguments(tmp_path / "case", record)

    result = create_pilot_evidence(**arguments)

    assert result.criteria_state == "INCOMPLETE_OR_BLOCKED"
    output = Path(arguments["output_directory"])
    summary = json.loads((output / PILOT_SUMMARY_NAME).read_text(encoding="ascii"))
    assert summary["criteria"]["recorded_successful_case_count"] == 3
    assert summary["criteria"]["success_identity_hashes_unique"] is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["cases"][0].update({"scan_file_count": 0}),
        lambda value: value["cases"][0].update({"state": "failed"}),
        lambda value: value["cases"][4]["hashes"].update({"dataset_manifest": None}),
        lambda value: value["cases"][5]["hashes"].update({"command_hash": None}),
        lambda value: value["cases"][5].update(
            {"preflight": {"status": "not_observed", "code": "NOT_OBSERVED"}}
        ),
        lambda value: value["cases"][3].update({"test": {"status": "passed", "code": "NONE"}}),
        lambda value: value["cases"][4].update({"preflight": {"status": "passed", "code": "NONE"}}),
        lambda value: value["capacity_retention"].update({"work_usage_bucket": "not_observed"}),
        lambda value: value["operator_documentation"].update({"restricted_record_sha256": None}),
        lambda value: value["cases"][0].update({"external_command_error_codes": ["NONE"]}),
        lambda value: value["cases"][0].update(
            {"run_transitions": [value["cases"][0]["run_transitions"][-1]]}
        ),
        lambda value: value["cases"][0].update({"observed_at": "2026-07-19T07:01:10Z"}),
        lambda value: value["cases"][0].update(
            {
                "run_transitions": [
                    {
                        "status": "pending",
                        "observed_at": "2026-07-19T07:01:00Z",
                        "return_code": None,
                    },
                    {
                        "status": "failed",
                        "observed_at": "2026-07-19T07:01:10Z",
                        "return_code": 1,
                    },
                    {
                        "status": "succeeded",
                        "observed_at": "2026-07-19T07:01:20Z",
                        "return_code": 0,
                    },
                ]
            }
        ),
    ],
)
def test_ready_record_requires_positive_counts_case_provenance_and_one_terminal_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: object,
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    assert callable(mutate)
    mutate(record)
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "sanitized_pilot_record"}
    assert not Path(arguments["output_directory"]).exists()


def test_friction_and_corrective_action_states_cannot_contradict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    record["friction_review_status"] = "recorded_with_findings"
    record["friction"] = [
        {
            "friction_id": "friction-001",
            "step": "preflight",
            "impact": "moderate",
            "status": "open",
            "action_id": "action-001",
        }
    ]
    record["corrective_actions"] = [
        {
            "action_id": "action-001",
            "friction_id": "friction-001",
            "owner_role": "runtime_owner",
            "priority": "p2",
            "status": "completed",
            "due_date": "2026-07-20",
            "verification_method": "controlled_rerun",
            "restricted_record_sha256": "1" * 64,
        }
    ]
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "sanitized_pilot_record"}


def test_unreferenced_corrective_action_cannot_hide_behind_resolved_friction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    record["friction_review_status"] = "recorded_with_findings"
    record["friction"] = [
        {
            "friction_id": "friction-001",
            "step": "preflight",
            "impact": "blocking",
            "status": "resolved",
            "action_id": None,
        }
    ]
    record["corrective_actions"] = [
        {
            "action_id": "action-001",
            "friction_id": "friction-001",
            "owner_role": "runtime_owner",
            "priority": "p0",
            "status": "open",
            "due_date": "2026-07-20",
            "verification_method": "controlled_rerun",
            "restricted_record_sha256": "1" * 64,
        }
    ]
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "sanitized_pilot_record"}


def test_semantically_identical_record_order_and_format_are_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    first_record = ready_record()
    second_record = ready_record()
    second_record["cases"] = list(reversed(second_record["cases"]))
    second_record["drills"] = list(reversed(second_record["drills"]))
    second_record["owner_assignments"] = list(reversed(second_record["owner_assignments"]))

    first = create_arguments(tmp_path / "first", first_record)
    second = create_arguments(tmp_path / "second", second_record)
    second["output_directory"] = Path(second["output_directory"]).parent / "other-name"
    Path(second["sanitized_record"]).write_text(
        json.dumps(second_record, separators=(",", ":")), encoding="utf-8"
    )

    create_pilot_evidence(**first)
    create_pilot_evidence(**second)

    assert bundle_bytes(Path(first["output_directory"])) == bundle_bytes(
        Path(second["output_directory"])
    )


def test_create_only_destination_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    output = Path(arguments["output_directory"])
    output.mkdir(mode=0o700)
    marker = output / "owned.txt"
    marker.write_text("keep", encoding="ascii")

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert marker.read_text(encoding="ascii") == "keep"
    assert list(output.iterdir()) == [marker]


def test_changed_m61_evidence_is_rejected_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    verifications = iter(
        [
            {
                "release_id": support.RELEASE_ID,
                "source_git_commit": COMMIT,
                "evidence_manifest_sha256": support.ACCEPTANCE_MANIFEST,
            },
            {
                "release_id": support.RELEASE_ID,
                "source_git_commit": COMMIT,
                "evidence_manifest_sha256": "f" * 64,
            },
        ]
    )
    monkeypatch.setattr(
        pilot,
        "verify_release_acceptance_evidence",
        lambda _path: next(verifications),
    )

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "m61_evidence_changed"}
    assert not Path(arguments["output_directory"]).exists()


def test_changed_repository_commit_is_rejected_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    commits = iter([COMMIT, "f" * 40])
    monkeypatch.setattr(
        pilot,
        "resolve_clean_repository_commit",
        lambda *_args, **_kwargs: next(commits),
    )

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "repository_changed"}
    assert not Path(arguments["output_directory"]).exists()


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda value: value.update({"hostname": PRIVATE_SENTINEL}), "sanitized_pilot_record"),
        (lambda value: value["cases"].pop(), "sanitized_pilot_record"),
        (
            lambda value: value["cases"][0].update(
                {"state": "succeeded", "observed_at": "2026-07-19T07:00:00Z"}
            ),
            "sanitized_pilot_record",
        ),
        (
            lambda value: value["expected_evidence"].update(
                {"candidate_manifest_sha256": "f" * 64}
            ),
            "m61_evidence_binding",
        ),
        (
            lambda value: value.update(
                {"backup_restore": {"status": "passed", "restricted_record_sha256": None}}
            ),
            "sanitized_pilot_record",
        ),
        (
            lambda value: value["cases"][0]["reported_audit"].update({"order_status": "failed"}),
            "sanitized_pilot_record",
        ),
        (
            lambda value: value["capacity_retention"].update(
                {"capacity_decision": "blocked", "retention_decision": "pending"}
            ),
            "sanitized_pilot_record",
        ),
    ],
)
def test_invalid_or_mismatched_records_fail_closed_without_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: object,
    reason: str,
) -> None:
    patch_external_bindings(monkeypatch)
    record = incomplete_record()
    assert callable(mutate)
    mutate(record)
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": reason}
    assert not Path(arguments["output_directory"]).exists()


def test_offline_verifier_rejects_report_tampering_even_with_resealed_checksums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    create_pilot_evidence(**arguments)
    output = Path(arguments["output_directory"])
    report = output / PILOT_REPORT_NAME
    report.write_bytes(report.read_bytes().replace(b"BLOCKED", b"APPROVED"))
    from biopipe.release_evidence.checksums import checksum_payloads

    payloads = {
        name: (output / name).read_bytes() for name in (PILOT_SUMMARY_NAME, PILOT_REPORT_NAME)
    }
    (output / "SHA256SUMS").write_bytes(checksum_payloads(payloads))

    with pytest.raises(BioPipeError) as raised:
        verify_pilot_evidence(output)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "review_draft_projection"}
