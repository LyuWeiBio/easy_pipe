"""Strict, synthetic real-host evidence inputs shared by focused tests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, fields
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest

import biopipe.release_evidence.real_host as real_host
from biopipe.execution import CoreArtifactHashes, compute_project_hash
from biopipe.release_evidence.checksums import render_checksum_manifest
from biopipe.release_evidence.generator import EVIDENCE_MANIFEST_NAME, EXPECTED_BUNDLE_NAMES
from biopipe.release_evidence.real_host import RealHostEvidenceInputs
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
CREATED_AT = "2026-07-18T09:00:00Z"
PRIVATE_SENTINEL = "patient-SAMPLE-ALPHA__private-host.internal__never-export"

_CHECK_NAMES = (
    "cache_writable",
    "container",
    "disk_space",
    "host_relationship",
    "output_dir_writable",
    "path_mapping",
    "rawdata_readable",
    "runtime",
    "ssh",
    "workdir_writable",
)
_AUDIT_SEQUENCE = (
    "REAL_DATA_APPROVED",
    "PIPELINE_DEPLOYED",
    "RUN_SUBMISSION_STARTED",
    "RUN_SUBMITTED",
    "RUN_STATUS_QUERIED",
    "RUN_COMPLETED",
)
_AUDIT_STATUS = {
    "REAL_DATA_APPROVED": "success",
    "PIPELINE_DEPLOYED": "success",
    "RUN_SUBMISSION_STARTED": "started",
    "RUN_SUBMITTED": "success",
    "RUN_STATUS_QUERIED": "success",
    "RUN_COMPLETED": "success",
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _json_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


@dataclass(slots=True)
class RealHostCase:
    """One internally bound set of private operator inputs."""

    repository: Path
    candidate_evidence: Path
    output_parent: Path
    inputs: RealHostEvidenceInputs

    def create_arguments(self, output: Path) -> list[str]:
        arguments = [
            "create",
            "--repository",
            str(self.repository),
            "--candidate-evidence",
            str(self.candidate_evidence),
            "--output",
            str(output),
            "--created-at",
            CREATED_AT,
        ]
        for field in fields(self.inputs):
            arguments.extend(
                [
                    f"--{field.name.replace('_', '-')}",
                    str(getattr(self.inputs, field.name)),
                ]
            )
        return arguments

    def rewrite_json(self, role: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        path = getattr(self.inputs, role)
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_bytes(_json_bytes(value))

    def bundle_bytes(self, output: Path) -> bytes:
        return b"".join(path.read_bytes() for path in sorted(output.iterdir()))


def build_real_host_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RealHostCase:
    """Write realistic reports with all cross-record bindings satisfied."""

    root = tmp_path.resolve()
    root.mkdir(parents=True, exist_ok=True)
    repository = root / f"repository-{PRIVATE_SENTINEL}"
    repository.mkdir()
    candidate_evidence = root / f"candidate-{PRIVATE_SENTINEL}"
    candidate_evidence.mkdir()
    private = root / f"operator-inputs-{PRIVATE_SENTINEL}"
    private.mkdir(mode=0o700)
    output_parent = root / "published"
    output_parent.mkdir(mode=0o700)

    binary_payloads = {
        "bioprobe": b"#!/usr/bin/env python3\nPK\x03\x04probe\n" + PRIVATE_SENTINEL.encode(),
        "bioexec": b"#!/usr/bin/env python3\nPK\x03\x04executor\n" + PRIVATE_SENTINEL.encode(),
    }
    binary_paths: dict[str, Path] = {}
    for role, payload in binary_payloads.items():
        path = private / f"{role}-{PRIVATE_SENTINEL}.pyz"
        path.write_bytes(payload)
        binary_paths[role] = path

    candidate = {
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
        "schema_catalog_sha256": "b" * 64,
        "schema_catalog_file_sha256": "c" * 64,
        "source_archive_sha256": "d" * 64,
        "wheel_sha256": "e" * 64,
        "sdist_sha256": "f" * 64,
        "bioprobe_sha256": _sha256(binary_payloads["bioprobe"]),
        "bioexec_sha256": _sha256(binary_payloads["bioexec"]),
        "created_at": "2026-07-18T07:00:00Z",
        "created_by": "private-host-operator",
        "record_state": "DRAFT_UNREVIEWED",
        "release_signoff_status": "pending",
    }
    candidate_payload = _json_bytes(candidate)
    (candidate_evidence / "candidate.json").write_bytes(candidate_payload)
    candidate_hashes = {
        name: ("9" * 64) for name in EXPECTED_BUNDLE_NAMES - {EVIDENCE_MANIFEST_NAME}
    }
    candidate_hashes["candidate.json"] = _sha256(candidate_payload)
    candidate_manifest = render_checksum_manifest(candidate_hashes)
    (candidate_evidence / EVIDENCE_MANIFEST_NAME).write_bytes(candidate_manifest)

    result_root = root / f"remote-results-{PRIVATE_SENTINEL}"

    profile = {
        "profile_version": "1.0",
        "profile_id": "real-host-profile",
        "source_host": "remote-source",
        "execution_host": "remote-source",
        "ssh_alias": "remote-source",
        "username": "private-operator",
        "port": 22,
        "bioexec_path": "~/.local/bin/bioexec.pyz",
        "approval_signer": {
            "key_id": "controller-key",
            "key_file": f"/controller-private/{PRIVATE_SENTINEL}/approval.key",
        },
        "allowed_roots": {
            "deploy": ("/remote/deploy",),
            "work": ("/remote/work",),
            "output": (str(result_root),),
            "cache": ("/remote/cache",),
        },
        "runtime": {
            "executor": "local",
            "workflow_engine": "nextflow",
            "container_engine": "docker",
        },
        "containers": {
            "fastp": {
                "image": "quay.io/biocontainers/fastp:0.23.4--h5f740d0_0",
                "digest": "sha256:" + "7" * 64,
                "local_path": None,
                "file_sha256": None,
            }
        },
        "disk_threshold": {"minimum_free_bytes": 10 * 1024**3},
        "preflight_max_age_seconds": 900,
        "path_mapping": (),
    }
    profile_payload = _json_bytes(profile)
    profile_path = private / "execution-profile.private.json"
    profile_path.write_bytes(profile_payload)

    core_hashes = {
        "dataset_manifest": "1" * 64,
        "pipeline_spec": "2" * 64,
        "execution_plan": "3" * 64,
        "software_lock": "4" * 64,
        "execution_profile": _sha256(profile_payload),
    }
    project_hash = compute_project_hash(CoreArtifactHashes.model_validate(core_hashes))
    static_hashes = {
        "dataset.manifest.resolved.json": core_hashes["dataset_manifest"],
        "execution.plan.yaml": core_hashes["execution_plan"],
        "pipeline.spec.yaml": core_hashes["pipeline_spec"],
        "software.lock.yaml": core_hashes["software_lock"],
    }
    static = {
        "report_version": "1.0",
        "validator": "static-generated-project",
        "project_directory": f"/remote/private/{PRIVATE_SENTINEL}",
        "status": "valid",
        "checked_artifacts": sorted(static_hashes),
        "artifact_hashes": static_hashes,
        "output_target_checked": f"/remote/results/{PRIVATE_SENTINEL}",
        "findings": [],
    }

    def workflow_report(mode: str) -> dict[str, object]:
        return {
            "report_version": "1.0",
            "mode": mode,
            "status": "passed",
            "code": "OK",
            "layout": "paired_end",
            "trimming_enabled": False,
            "synthetic_data_only": True,
            "checks": [],
            "outputs": [],
            "remediation": [],
        }

    validation = {
        "report_version": "1.0",
        "command": "validate",
        "status": "passed",
        "code": "OK",
        "project_directory": static["project_directory"],
        "report_path": "reports/validation.json",
        "synthetic_data_only": True,
        "static_validation": static,
        "runtime_validation": workflow_report("validate"),
        "remediation": [],
    }
    test = {
        "report_version": "1.0",
        "command": "test",
        "profile": "test",
        "status": "passed",
        "code": "OK",
        "project_directory": static["project_directory"],
        "report_path": "reports/test.json",
        "synthetic_data_only": True,
        "static_validation": static,
        "runs": {mode: workflow_report(mode) for mode in ("e2e", "stub")},
        "remediation": [],
    }
    preflight = {
        "report_version": "1.0",
        "status": "passed",
        "checked_at": "2026-07-18T08:00:00Z",
        "profile_id": profile["profile_id"],
        "source_host": profile["source_host"],
        "execution_host": profile["execution_host"],
        "artifact_hashes": core_hashes,
        "preflight_id": "preflight-real-host",
        "project_hash": project_hash,
        "input_count": 2,
        "input_set_hash": "5" * 64,
        "checks": [{"name": name, "status": "passed"} for name in _CHECK_NAMES],
    }
    run_id = "run-" + "6" * 32
    command_hash = "8" * 64
    environment_hash = "9" * 64
    bundle_hash = "a" * 64
    run = {
        "report_version": "1.0",
        "status": "succeeded",
        "run_id": run_id,
        "project_id": "synthetic-project",
        "profile_id": profile["profile_id"],
        "authorization_id": "authorization-real-host",
        "deployment_id": "deployment-" + "b" * 32,
        "remote_work_dir": "/remote/work/synthetic-project",
        "result_dir": str(result_root / "synthetic-project"),
        "project_hash": project_hash,
        "bundle_hash": bundle_hash,
        "submitted_at": "2026-07-18T08:20:00Z",
        "resume_from": None,
        "command_hash": command_hash,
        "environment_hash": environment_hash,
    }
    status = {
        "report_version": "1.0",
        "run_id": run_id,
        "status": "succeeded",
        "return_code": 0,
        "command_hash": command_hash,
        "environment_hash": environment_hash,
        "checked_at": "2026-07-18T08:30:00Z",
    }

    payloads: dict[str, bytes] = {
        "validation_report": _json_bytes(validation),
        "test_report": _json_bytes(test),
        "preflight_report": _json_bytes(preflight),
        "run_report": _json_bytes(run),
        "status_report": _json_bytes(status),
        "execution_profile": profile_payload,
        "approval_denial": _json_bytes(
            {
                "error": {
                    "code": "APPROVAL_REQUIRED",
                    "context": {"private_marker": PRIVATE_SENTINEL},
                    "message": f"Private denial detail {PRIVATE_SENTINEL}",
                    "remediation": ["Supply explicit operator approval."],
                    "severity": "blocking",
                }
            }
        ),
        "probe_health": _json_line(
            {
                "error": None,
                "protocol_version": "1.0",
                "request_id": "real-host-probe-health",
                "result": {
                    "operation": "health",
                    "status": "ok",
                    "protocol_version": "1.0",
                    "probe_version": PROBE_VERSION,
                    "private_detail": PRIVATE_SENTINEL,
                },
                "return_code": 0,
                "success": True,
            }
        ),
        "executor_health": _json_line(
            {
                "error": None,
                "protocol_version": "1.0",
                "request_id": "real-host-executor-health",
                "result": {
                    "status": "ok",
                    "protocol_version": "1.0",
                    "agent_version": REMOTE_EXECUTOR_VERSION,
                    "profile_id": profile["profile_id"],
                    "profile_hash": _sha256(profile_payload),
                    "private_detail": PRIVATE_SENTINEL,
                },
                "return_code": 0,
                "success": True,
            }
        ),
        "multiqc_report": (
            b"<!doctype html><html><body>Synthetic MultiQC<!-- "
            + PRIVATE_SENTINEL.encode()
            + b" --></body></html>\n"
        ),
        "multiqc_data": _json_bytes(
            {
                "report_general_stats_data": {
                    "fastqc": {
                        "anonymous-sample": {
                            "private_marker": PRIVATE_SENTINEL,
                            "total_sequences": 2,
                        }
                    }
                }
            }
        ),
    }

    expected_inputs = {
        **core_hashes,
        "bundle": bundle_hash,
        "preflight_report": _sha256(payloads["preflight_report"]),
        "test_report": _sha256(payloads["test_report"]),
        "validation_report": _sha256(payloads["validation_report"]),
    }
    audit_events = [
        {
            "schema_version": "1.0",
            "event_id": str(UUID(int=1)),
            "timestamp": "2026-07-18T07:50:00Z",
            "event_type": "LOCAL_GATES_COMPLETED",
            "project_id": "synthetic-project",
            "actor": "operator-a",
            "input_hashes": {},
            "output_hashes": {},
            "status": "success",
            "summary": "Private local gate detail retained by the operator.",
        }
    ]
    audit_timestamps = (
        "2026-07-18T08:20:01Z",
        "2026-07-18T08:20:02Z",
        "2026-07-18T08:20:03Z",
        "2026-07-18T08:20:04Z",
        "2026-07-18T08:30:01Z",
        "2026-07-18T08:30:02Z",
    )
    for index, (event_type, timestamp) in enumerate(
        zip(_AUDIT_SEQUENCE, audit_timestamps, strict=True), start=2
    ):
        run_reference = {run_id: _sha256(run_id.encode("ascii"))}
        output_hashes: dict[str, str]
        if event_type == "REAL_DATA_APPROVED":
            output_hashes = {}
        elif event_type == "PIPELINE_DEPLOYED":
            output_hashes = {"bundle": bundle_hash}
        elif event_type in {"RUN_SUBMISSION_STARTED", "RUN_STATUS_QUERIED"}:
            output_hashes = run_reference
        elif event_type == "RUN_SUBMITTED":
            output_hashes = {
                "bundle": bundle_hash,
                "command": command_hash,
                "environment": environment_hash,
                **run_reference,
            }
        else:
            output_hashes = {
                "command": command_hash,
                "environment": environment_hash,
                "return_code": _sha256(b"0"),
                **run_reference,
            }
        audit_events.append(
            {
                "schema_version": "1.0",
                "event_id": str(UUID(int=index)),
                "timestamp": timestamp,
                "event_type": event_type,
                "project_id": "synthetic-project",
                "actor": "operator-a",
                "input_hashes": expected_inputs,
                "output_hashes": output_hashes,
                "status": _AUDIT_STATUS[event_type],
                "summary": f"Synthetic {event_type.lower()} event.",
            }
        )
    audit_before = _json_line(audit_events[0])
    audit_final = b"".join(_json_line(event) for event in audit_events)
    payloads.update(
        {
            "audit_before_denial": audit_before,
            "audit_after_denial": audit_before,
            "audit_final": audit_final,
        }
    )

    paths: dict[str, Path] = {}
    for role, payload in payloads.items():
        if role == "multiqc_report":
            path = result_root / "synthetic-project" / "multiqc" / "multiqc_report.html"
        elif role == "multiqc_data":
            path = (
                result_root / "synthetic-project" / "multiqc" / "multiqc_data" / "multiqc_data.json"
            )
        else:
            path = private / f"{role}-{PRIVATE_SENTINEL}.private"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        paths[role] = path
    paths.update(binary_paths)
    inputs = RealHostEvidenceInputs(**paths)

    monkeypatch.setattr(
        real_host,
        "verify_release_evidence",
        lambda _directory: SimpleNamespace(
            release_id=RELEASE_ID,
            git_commit=COMMIT,
            evidence_manifest_sha256=_sha256(candidate_manifest),
        ),
    )
    monkeypatch.setattr(real_host, "resolve_clean_repository_commit", lambda _repository: COMMIT)
    monkeypatch.setattr(
        real_host,
        "validate_runtime_repository_binding",
        lambda _repository, _commit: None,
    )
    return RealHostCase(
        repository=repository,
        candidate_evidence=candidate_evidence,
        output_parent=output_parent,
        inputs=inputs,
    )


__all__ = [
    "COMMIT",
    "CREATED_AT",
    "PRIVATE_SENTINEL",
    "RELEASE_ID",
    "RealHostCase",
    "build_real_host_case",
]
