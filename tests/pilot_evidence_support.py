"""Strict synthetic inputs for internal-pilot evidence tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import biopipe.release_evidence.pilot as pilot
from biopipe.execution import CoreArtifactHashes, compute_project_hash
from biopipe.release_evidence.models import EvidenceVerification
from biopipe.release_evidence.pilot_record import build_unexecuted_pilot_record
from biopipe.version import (
    CLI_CONTRACT_VERSION,
    COMPILER_VERSION,
    CONTROLLER_VERSION,
    MVP_SCHEMA_VERSION,
    PROBE_VERSION,
    REGISTRY_VERSION,
    REMOTE_EXECUTOR_VERSION,
)

RELEASE_ID = "0.1.0-rc1"
COMMIT = "a" * 40
CANDIDATE_MANIFEST = "b" * 64
ACCEPTANCE_MANIFEST = "c" * 64
REAL_HOST_MANIFEST = "d" * 64
RECORDED_AT = "2026-07-19T08:00:00Z"
CREATED_AT = "2026-07-19T09:00:00Z"
PRIVATE_SENTINEL = "patient-SAMPLE-ALPHA__private-host.internal__never-export"


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha(character: str) -> str:
    return character * 64


def _unobserved_gate() -> dict[str, str]:
    return {"status": "not_observed", "code": "NOT_OBSERVED"}


def _passed_gate() -> dict[str, str]:
    return {"status": "passed", "code": "NONE"}


def _empty_audit() -> dict[str, object]:
    return {
        "parse_status": "not_performed",
        "order_status": "not_performed",
        "authorization_binding_status": "not_performed",
        "terminal_binding_status": "not_performed",
    }


def _passed_audit() -> dict[str, object]:
    return {
        "parse_status": "passed",
        "order_status": "passed",
        "authorization_binding_status": "passed",
        "terminal_binding_status": "passed",
    }


def _empty_hashes() -> dict[str, None]:
    return {
        "dataset_manifest": None,
        "pipeline_spec": None,
        "execution_plan": None,
        "software_lock": None,
        "execution_profile": None,
        "validation_report": None,
        "test_report": None,
        "preflight_report": None,
        "run_report": None,
        "status_report": None,
        "audit": None,
        "project_hash": None,
        "bundle_hash": None,
        "command_hash": None,
        "environment_hash": None,
    }


def _unexecuted_case(case_id: str, scenario: str) -> dict[str, object]:
    return {
        "case_id": case_id,
        "scenario": scenario,
        "state": "unexecuted",
        "data_classification": "synthetic",
        "observed_at": None,
        "scan_file_count": None,
        "scan_duration_ms": None,
        "manifest_sample_count": None,
        "manifest_lane_count": None,
        "validation": _unobserved_gate(),
        "test": _unobserved_gate(),
        "preflight": _unobserved_gate(),
        "run_transitions": [],
        "work_usage_bucket": "not_observed",
        "output_usage_bucket": "not_observed",
        "external_command_timeout_count": 0,
        "external_command_error_codes": [],
        "reported_audit": _empty_audit(),
        "hashes": _empty_hashes(),
        "run_id_sha256": None,
        "attribution_record_sha256": None,
        "controlled_evidence_sha256": None,
    }


def incomplete_record() -> dict[str, Any]:
    return build_unexecuted_pilot_record(
        pilot_id="pilot-20260719-001",
        environment_id="env-001",
        recorded_at=RECORDED_AT,
        release_id=RELEASE_ID,
        source_git_commit=COMMIT,
        candidate_manifest_sha256=CANDIDATE_MANIFEST,
        release_acceptance_manifest_sha256=ACCEPTANCE_MANIFEST,
        real_host_manifest_sha256=REAL_HOST_MANIFEST,
    ).model_dump(mode="json")


def _success_hashes(seed: int) -> dict[str, str]:
    digits = "123456789abcdef"
    selected = [sha(digits[(seed + offset) % len(digits)]) for offset in range(15)]
    core = CoreArtifactHashes(
        dataset_manifest=selected[0],
        pipeline_spec=selected[1],
        execution_plan=selected[2],
        software_lock=selected[3],
        execution_profile=selected[4],
    )
    return {
        "dataset_manifest": core.dataset_manifest,
        "pipeline_spec": core.pipeline_spec,
        "execution_plan": core.execution_plan,
        "software_lock": core.software_lock,
        "execution_profile": core.execution_profile,
        "validation_report": selected[5],
        "test_report": selected[6],
        "preflight_report": selected[7],
        "run_report": selected[8],
        "status_report": selected[9],
        "audit": selected[10],
        "project_hash": compute_project_hash(core),
        "bundle_hash": selected[11],
        "command_hash": selected[12],
        "environment_hash": selected[13],
    }


def ready_record() -> dict[str, Any]:
    value = incomplete_record()
    cases: list[dict[str, Any]] = []
    for index, scenario in enumerate(pilot._REQUIRED_CASE_SCENARIOS, start=1):
        item = _unexecuted_case(f"case-{index:03d}", scenario)
        item.update(
            {
                "observed_at": f"2026-07-19T07:{index:02d}:30Z",
                "scan_file_count": index * 2,
                "scan_duration_ms": index * 100,
                "manifest_sample_count": index,
                "manifest_lane_count": index * 2,
                "controlled_evidence_sha256": sha("e"),
            }
        )
        if scenario in pilot._SUCCESS_SCENARIOS:
            item.update(
                {
                    "state": "succeeded",
                    "validation": _passed_gate(),
                    "test": _passed_gate(),
                    "preflight": _passed_gate(),
                    "run_transitions": [
                        {
                            "status": "pending",
                            "observed_at": f"2026-07-19T07:{index:02d}:00Z",
                            "return_code": None,
                        },
                        {
                            "status": "succeeded",
                            "observed_at": f"2026-07-19T07:{index:02d}:20Z",
                            "return_code": 0,
                        },
                    ],
                    "work_usage_bucket": "under_1_gib",
                    "output_usage_bucket": "under_1_gib",
                    "reported_audit": _passed_audit(),
                    "hashes": _success_hashes(index),
                    "run_id_sha256": sha(str(index)),
                }
            )
        elif scenario == "missing_mate":
            item.update(
                {
                    "state": "blocked",
                    "validation": {"status": "blocked", "code": "MISSING_MATE"},
                }
            )
        elif scenario == "ambiguous_naming":
            resolved_hashes = _empty_hashes()
            resolved_hashes["dataset_manifest"] = sha("7")
            item.update(
                {
                    "state": "resolved",
                    "validation": _passed_gate(),
                    "attribution_record_sha256": sha("f"),
                    "hashes": resolved_hashes,
                }
            )
        else:
            failure_hashes = _success_hashes(index)
            item.update(
                {
                    "state": "failed_queryable",
                    "validation": _passed_gate(),
                    "test": _passed_gate(),
                    "preflight": _passed_gate(),
                    "run_transitions": [
                        {
                            "status": "pending",
                            "observed_at": "2026-07-19T07:06:00Z",
                            "return_code": None,
                        },
                        {
                            "status": "failed",
                            "observed_at": "2026-07-19T07:06:20Z",
                            "return_code": 1,
                        },
                    ],
                    "work_usage_bucket": "under_1_gib",
                    "output_usage_bucket": "under_1_gib",
                    "reported_audit": _passed_audit(),
                    "hashes": failure_hashes,
                    "run_id_sha256": sha("8"),
                }
            )
        cases.append(item)
    value["cases"] = cases
    value["drills"] = [
        {
            "drill_id": "drill-001",
            "drill_type": "host_key_mismatch",
            "state": "recovered",
            "expected_code": "SSH_HOST_KEY_MISMATCH",
            "observed_code": "SSH_HOST_KEY_MISMATCH",
            "observed_at": "2026-07-19T07:30:00Z",
            "control_relaxed": False,
            "controlled_evidence_sha256": sha("1"),
        },
        {
            "drill_id": "drill-002",
            "drill_type": "stale_preflight",
            "state": "recovered",
            "expected_code": "PREFLIGHT_STALE",
            "observed_code": "PREFLIGHT_STALE",
            "observed_at": "2026-07-19T07:31:00Z",
            "control_relaxed": False,
            "controlled_evidence_sha256": sha("2"),
        },
        {
            "drill_id": "drill-003",
            "drill_type": "low_disk_space",
            "state": "recovered",
            "expected_code": "INSUFFICIENT_SPACE",
            "observed_code": "INSUFFICIENT_SPACE",
            "observed_at": "2026-07-19T07:32:00Z",
            "control_relaxed": False,
            "controlled_evidence_sha256": sha("3"),
        },
    ]
    value["entry_gate"] = {
        "status": "recorded_complete_in_restricted_system",
        "restricted_record_sha256": sha("4"),
    }
    value["owner_assignments"] = [
        {
            "role": role,
            "status": "recorded_in_restricted_system",
            "restricted_record_sha256": sha(str(index)),
        }
        for index, role in enumerate(pilot._OWNER_ROLES, start=5)
    ]
    value["capacity_retention"] = {
        "deploy_usage_bucket": "under_1_gib",
        "work_usage_bucket": "1_to_10_gib",
        "output_usage_bucket": "under_1_gib",
        "cache_usage_bucket": "1_to_10_gib",
        "capacity_decision": "approved",
        "retention_decision": "approved",
        "restricted_record_sha256": sha("a"),
    }
    value["backup_restore"] = {"status": "passed", "restricted_record_sha256": sha("b")}
    value["operator_documentation"] = {
        "result": "completed_from_documentation_only",
        "restricted_record_sha256": sha("c"),
    }
    value["friction_review_status"] = "recorded_none"
    value["next_recommendation"] = "request_independent_m62_review"
    return value


def write_candidate(candidate_root: Path) -> None:
    candidate_root.mkdir(mode=0o700)
    value = {
        "evidence_format_version": "1.0",
        "release_id": RELEASE_ID,
        "git_commit": COMMIT,
        "controller_version": CONTROLLER_VERSION,
        "probe_version": PROBE_VERSION,
        "remote_executor_version": REMOTE_EXECUTOR_VERSION,
        "compiler_version": COMPILER_VERSION,
        "registry_version": REGISTRY_VERSION,
        "schema_version": MVP_SCHEMA_VERSION,
        "cli_contract_version": CLI_CONTRACT_VERSION,
        "schema_catalog_sha256": sha("1"),
        "schema_catalog_file_sha256": sha("2"),
        "source_archive_sha256": sha("3"),
        "wheel_sha256": sha("4"),
        "sdist_sha256": sha("5"),
        "bioprobe_sha256": sha("6"),
        "bioexec_sha256": sha("7"),
        "created_at": "2026-07-18T07:00:00Z",
        "created_by": "pilot-operator",
        "record_state": "DRAFT_UNREVIEWED",
        "release_signoff_status": "pending",
    }
    (candidate_root / "candidate.json").write_bytes(json_bytes(value))


def patch_external_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    verification = EvidenceVerification(
        release_id=RELEASE_ID,
        git_commit=COMMIT,
        evidence_manifest_sha256=CANDIDATE_MANIFEST,
        file_count=18,
    )
    monkeypatch.setattr(pilot, "verify_release_evidence", lambda _path: verification)
    monkeypatch.setattr(
        pilot,
        "verify_release_acceptance_evidence",
        lambda _path: {
            "release_id": RELEASE_ID,
            "source_git_commit": COMMIT,
            "evidence_manifest_sha256": ACCEPTANCE_MANIFEST,
        },
    )
    monkeypatch.setattr(
        pilot,
        "verify_real_host_acceptance_evidence",
        lambda _path: {
            "release_id": RELEASE_ID,
            "source_git_commit": COMMIT,
            "evidence_manifest_sha256": REAL_HOST_MANIFEST,
        },
    )
    monkeypatch.setattr(pilot, "resolve_clean_repository_commit", lambda *_args, **_kwargs: COMMIT)
    monkeypatch.setattr(pilot, "validate_runtime_repository_binding", lambda *_args: None)


def create_arguments(root: Path, record: dict[str, Any]) -> dict[str, Path | str]:
    root.mkdir(mode=0o700)
    repository = root / f"repository-{PRIVATE_SENTINEL}"
    repository.mkdir(mode=0o700)
    candidate = root / f"candidate-{PRIVATE_SENTINEL}"
    write_candidate(candidate)
    acceptance = root / f"acceptance-{PRIVATE_SENTINEL}"
    acceptance.mkdir(mode=0o700)
    real_host = root / f"real-host-{PRIVATE_SENTINEL}"
    real_host.mkdir(mode=0o700)
    record_path = root / f"sanitized-record-{PRIVATE_SENTINEL}.json"
    record_path.write_bytes(json_bytes(record))
    record_path.chmod(0o600)
    output_parent = root / "published"
    output_parent.mkdir(mode=0o700)
    return {
        "repository": repository,
        "candidate_evidence": candidate,
        "release_acceptance_evidence": acceptance,
        "real_host_evidence": real_host,
        "sanitized_record": record_path,
        "output_directory": output_parent / "pilot-evidence",
        "created_at": CREATED_AT,
    }


def bundle_bytes(directory: Path) -> bytes:
    return b"".join(path.read_bytes() for path in sorted(directory.iterdir()))


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
