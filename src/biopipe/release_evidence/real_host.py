"""Create and verify privacy-safe operator real-host acceptance evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, Final, TypeVar, cast

from pydantic import BaseModel, ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution import (
    ExecutionProfile,
    PreflightReport,
    RunReport,
    StatusReport,
    compute_project_hash,
)
from biopipe.models import AuditEvent
from biopipe.release_evidence.checksums import (
    checksum_payloads,
    hash_release_artifact,
    parse_checksum_manifest,
    read_bounded_regular,
)
from biopipe.release_evidence.generator import (
    EVIDENCE_MANIFEST_NAME,
    EXPECTED_BUNDLE_NAMES,
    resolve_clean_repository_commit,
    validate_runtime_repository_binding,
    verify_release_evidence,
)
from biopipe.release_evidence.models import ReleaseCandidate
from biopipe.release_evidence.store import EvidenceBundleStore
from biopipe.report_models import TestCommandReport, ValidationCommandReport

REAL_HOST_EVIDENCE_NAMES: Final[frozenset[str]] = frozenset(
    {"SHA256SUMS", "real-host-acceptance.json"}
)
_CORE_NAMES: Final[frozenset[str]] = frozenset({"real-host-acceptance.json"})
_MAX_INPUT_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_MULTIQC_BYTES: Final[int] = 16 * 1024 * 1024
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_RELEASE_ID = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-rc[1-9][0-9]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_PREFLIGHT_CHECKS: Final[frozenset[str]] = frozenset(
    {
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
    }
)
_AUDIT_SEQUENCE: Final[tuple[str, ...]] = (
    "REAL_DATA_APPROVED",
    "PIPELINE_DEPLOYED",
    "RUN_SUBMISSION_STARTED",
    "RUN_SUBMITTED",
    "RUN_STATUS_QUERIED",
    "RUN_COMPLETED",
)
_RUNTIME_AUDIT_TYPES: Final[frozenset[str]] = frozenset(
    {
        *_AUDIT_SEQUENCE,
        "PIPELINE_DEPLOY_FAILED",
        "RUN_FAILED",
        "RUN_RESUMED",
        "RUN_SUBMISSION_ABANDONED",
        "RUN_SUBMISSION_FAILED",
    }
)
_AUDIT_STATUS: Final[dict[str, str]] = {
    "PIPELINE_DEPLOYED": "success",
    "REAL_DATA_APPROVED": "success",
    "RUN_COMPLETED": "success",
    "RUN_STATUS_QUERIED": "success",
    "RUN_SUBMISSION_STARTED": "started",
    "RUN_SUBMITTED": "success",
}
_CHECKS: Final[dict[str, str]] = {
    "approval_denial": "passed",
    "approved_run": "passed",
    "audit_binding": "passed",
    "audit_unchanged_after_denial": "passed",
    "bioexec_identity": "passed",
    "bioprobe_identity": "passed",
    "candidate_evidence": "passed",
    "clean_repository": "passed",
    "executor_force_command_health": "passed",
    "multiqc_outputs": "passed",
    "preflight": "passed",
    "probe_force_command_health": "passed",
    "test_gate": "passed",
    "validation_gate": "passed",
}
_ARTIFACT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "approval_denial",
        "audit_after_denial",
        "audit_before_denial",
        "audit_final",
        "bioexec",
        "bioprobe",
        "candidate_evidence_manifest",
        "candidate_record",
        "execution_profile",
        "executor_health",
        "multiqc_data",
        "multiqc_report",
        "preflight_report",
        "probe_health",
        "run_report",
        "status_report",
        "test_report",
        "validation_report",
    }
)
_LIMITATIONS: Final[tuple[str, ...]] = (
    "force_command_configuration_pending_independent_review",
    "network_egress_control_pending_independent_review",
    "remote_artifact_bytes_pending_independent_review",
)
ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class RealHostEvidenceInputs:
    """Fixed-role private inputs consumed without serializing their paths."""

    validation_report: Path
    test_report: Path
    preflight_report: Path
    run_report: Path
    status_report: Path
    execution_profile: Path
    approval_denial: Path
    audit_before_denial: Path
    audit_after_denial: Path
    audit_final: Path
    probe_health: Path
    executor_health: Path
    multiqc_report: Path
    multiqc_data: Path
    bioprobe: Path
    bioexec: Path


def create_real_host_acceptance_evidence(
    *,
    repository: str | Path,
    candidate_evidence: str | Path,
    output_directory: str | Path,
    created_at: str,
    inputs: RealHostEvidenceInputs,
) -> dict[str, object]:
    """Validate one operator run and publish a sealed, still-blocked bundle."""

    created = _canonical_time(created_at, role="created_at")
    repository_path = Path(repository).absolute()
    candidate_root = Path(candidate_evidence).absolute()
    candidate_verification = verify_release_evidence(candidate_root)
    candidate_payload = read_bounded_regular(
        candidate_root / "candidate.json",
        role="candidate_record",
        limit_bytes=_MAX_INPUT_BYTES,
    )
    candidate_manifest = read_bounded_regular(
        candidate_root / EVIDENCE_MANIFEST_NAME,
        role="candidate_evidence_manifest",
        limit_bytes=_MAX_INPUT_BYTES,
    )
    try:
        candidate_hashes = parse_checksum_manifest(
            candidate_manifest,
            expected_names=EXPECTED_BUNDLE_NAMES - {EVIDENCE_MANIFEST_NAME},
        )
    except ValueError as exc:
        raise _validation_error("candidate_evidence_manifest") from exc
    if _sha256(
        candidate_manifest
    ) != candidate_verification.evidence_manifest_sha256 or candidate_hashes.get(
        "candidate.json"
    ) != _sha256(candidate_payload):
        raise _validation_error("candidate_record_binding")
    candidate = _load_model(candidate_payload, ReleaseCandidate, role="candidate_record")
    if (
        candidate.release_id != candidate_verification.release_id
        or candidate.git_commit != candidate_verification.git_commit
        or created < _canonical_time(candidate.created_at, role="candidate_created_at")
    ):
        raise _validation_error("candidate_identity")

    commit = resolve_clean_repository_commit(repository_path)
    if commit != candidate.git_commit:
        raise _validation_error("candidate_commit")
    validate_runtime_repository_binding(repository_path, commit)

    payloads = _read_inputs(inputs)
    validation = _load_model(
        payloads["validation_report"], ValidationCommandReport, role="validation_report"
    )
    test = _load_model(payloads["test_report"], TestCommandReport, role="test_report")
    preflight = _load_model(payloads["preflight_report"], PreflightReport, role="preflight_report")
    run = _load_model(payloads["run_report"], RunReport, role="run_report")
    status = _load_model(payloads["status_report"], StatusReport, role="status_report")
    profile = _load_model(payloads["execution_profile"], ExecutionProfile, role="execution_profile")
    _validate_gate_reports(validation, test, preflight)
    _validate_execution_binding(
        preflight=preflight,
        run=run,
        status=status,
        profile=profile,
        created=created,
        profile_payload=payloads["execution_profile"],
    )
    _validate_denial(
        payloads["approval_denial"],
        before=payloads["audit_before_denial"],
        after=payloads["audit_after_denial"],
        final=payloads["audit_final"],
    )
    _validate_health(
        payloads["probe_health"],
        payloads["executor_health"],
        candidate=candidate,
        profile=profile,
        profile_hash=hashlib.sha256(payloads["execution_profile"]).hexdigest(),
    )
    _validate_multiqc(
        payloads["multiqc_report"],
        payloads["multiqc_data"],
        report_path=inputs.multiqc_report,
        data_path=inputs.multiqc_data,
        run=run,
    )
    _validate_audit(
        payloads["audit_final"],
        run=run,
        status=status,
        preflight=preflight,
        validation_sha256=_sha256(payloads["validation_report"]),
        test_sha256=_sha256(payloads["test_report"]),
        preflight_sha256=_sha256(payloads["preflight_report"]),
        created=created,
    )

    bioprobe_sha256 = hash_release_artifact(inputs.bioprobe, "bioprobe")
    bioexec_sha256 = hash_release_artifact(inputs.bioexec, "bioexec")
    if bioprobe_sha256 != candidate.bioprobe_sha256 or bioexec_sha256 != candidate.bioexec_sha256:
        raise _validation_error("remote_artifact_identity")

    artifact_hashes = {name: _sha256(payload) for name, payload in payloads.items()}
    artifact_hashes.update(
        {
            "bioexec": bioexec_sha256,
            "bioprobe": bioprobe_sha256,
            "candidate_evidence_manifest": candidate_verification.evidence_manifest_sha256,
            "candidate_record": _sha256(candidate_payload),
        }
    )
    summary = {
        "acceptance_format_version": "1.0",
        "acceptance_status": "passed",
        "artifacts": dict(sorted(artifact_hashes.items())),
        "checks": _CHECKS,
        "container_engine": profile.runtime.container_engine,
        "created_at": created_at,
        "data_classification": "anonymous_synthetic_only",
        "evidence_status": "OPERATOR_GENERATED_UNREVIEWED",
        "independent_review_status": "PENDING_INDEPENDENT_REVIEW",
        "limitations": list(_LIMITATIONS),
        "network_claim": "remote_preflight_policy_passed_not_egress_attestation",
        "preflight_check_count": len(preflight.checks),
        "real_container_runtime_exercised": True,
        "real_remote_host_exercised": True,
        "real_ssh_exercised": True,
        "release_decision": "BLOCKED",
        "release_id": candidate.release_id,
        "source_git_commit": candidate.git_commit,
        "synthetic_remote_only": True,
    }
    _validate_summary(summary)
    summary_payload = _render_json(summary)
    _assert_sanitized(
        summary_payload,
        repository=repository_path,
        candidate_evidence=candidate_root,
        output_directory=Path(output_directory).absolute(),
        inputs=inputs,
    )
    bundle = {"real-host-acceptance.json": summary_payload}
    bundle["SHA256SUMS"] = checksum_payloads(bundle)

    if resolve_clean_repository_commit(repository_path) != commit:
        raise _validation_error("repository_changed")
    EvidenceBundleStore(output_directory).create(bundle)
    result = verify_real_host_acceptance_evidence(output_directory)
    return {**result, "status": "real_host_acceptance_evidence_created_unreviewed"}


def verify_real_host_acceptance_evidence(directory: str | Path) -> dict[str, object]:
    """Verify the fixed two-file bundle without Git, subprocess, or network access."""

    payloads = _read_evidence_directory(Path(directory).absolute())
    summary_payload = payloads["real-host-acceptance.json"]
    summary = _decode_json(summary_payload, role="real_host_acceptance")
    _validate_summary(summary)
    try:
        expected = parse_checksum_manifest(
            payloads["SHA256SUMS"],
            expected_names=_CORE_NAMES,
        )
    except ValueError as exc:
        raise _validation_error("checksum_manifest") from exc
    if expected != {"real-host-acceptance.json": _sha256(summary_payload)}:
        raise _validation_error("bundle_checksum")
    return {
        "acceptance_status": "passed",
        "evidence_manifest_sha256": _sha256(payloads["SHA256SUMS"]),
        "file_count": len(payloads),
        "release_decision": "BLOCKED",
        "release_id": summary["release_id"],
        "source_git_commit": summary["source_git_commit"],
        "status": "real_host_acceptance_evidence_verified_offline",
    }


def _read_inputs(inputs: RealHostEvidenceInputs) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for field in fields(inputs):
        name = field.name
        if name in {"bioprobe", "bioexec"}:
            continue
        limit = (
            _MAX_MULTIQC_BYTES if name in {"multiqc_report", "multiqc_data"} else _MAX_INPUT_BYTES
        )
        payloads[name] = read_bounded_regular(
            getattr(inputs, name),
            role=name,
            limit_bytes=limit,
        )
    return payloads


def _load_model(payload: bytes, model: type[ModelT], *, role: str) -> ModelT:
    try:
        return model.model_validate(_decode_json(payload, role=role))
    except (ValidationError, ValueError) as exc:
        raise _validation_error(role) from exc


def _validate_gate_reports(
    validation: ValidationCommandReport,
    test: TestCommandReport,
    preflight: PreflightReport,
) -> None:
    try:
        validation.require_gate_success()
        test.require_gate_success()
    except ValueError as exc:
        raise _validation_error("local_gate_reports") from exc
    preflight_names = {check.name for check in preflight.checks}
    if (
        validation.project_directory != test.project_directory
        or validation.static_validation.artifact_hashes != test.static_validation.artifact_hashes
        or preflight.status != "passed"
        or not preflight_names.issuperset(_REQUIRED_PREFLIGHT_CHECKS)
        or any(check.status != "passed" for check in preflight.checks)
    ):
        raise _validation_error("preflight_gate")
    artifact_names = {
        "dataset_manifest": "dataset.manifest.resolved.json",
        "execution_plan": "execution.plan.yaml",
        "pipeline_spec": "pipeline.spec.yaml",
        "software_lock": "software.lock.yaml",
    }
    observed = validation.static_validation.artifact_hashes
    if any(
        observed.get(filename) != getattr(preflight.artifact_hashes, role)
        for role, filename in artifact_names.items()
    ):
        raise _validation_error("project_artifact_binding")


def _validate_execution_binding(
    *,
    preflight: PreflightReport,
    run: RunReport,
    status: StatusReport,
    profile: ExecutionProfile,
    created: datetime,
    profile_payload: bytes,
) -> None:
    profile_hash = _sha256(profile_payload)
    expected_project_hash = compute_project_hash(preflight.artifact_hashes)
    expected_work_directory = str(PurePosixPath(profile.allowed_roots.work[0]) / run.project_id)
    expected_result_directory = str(PurePosixPath(profile.allowed_roots.output[0]) / run.project_id)
    preflight_time = _aware_utc(preflight.checked_at, role="preflight_checked_at")
    submitted_time = _aware_utc(run.submitted_at, role="run_submitted_at")
    status_time = _aware_utc(status.checked_at, role="status_checked_at")
    if (
        profile_hash != preflight.artifact_hashes.execution_profile
        or profile.profile_id != preflight.profile_id
        or profile.source_host != preflight.source_host
        or profile.execution_host != preflight.execution_host
        or preflight.project_hash != expected_project_hash
        or run.profile_id != profile.profile_id
        or run.project_hash != expected_project_hash
        or len(profile.allowed_roots.work) != 1
        or len(profile.allowed_roots.output) != 1
        or run.remote_work_dir != expected_work_directory
        or run.result_dir != expected_result_directory
        or status.run_id != run.run_id
        or status.command_hash != run.command_hash
        or status.environment_hash != run.environment_hash
        or run.status == "failed"
        or status.status != "succeeded"
        or status.return_code != 0
        or preflight_time > submitted_time
        or submitted_time > status_time
        or status_time.replace(microsecond=0) > created
    ):
        raise _validation_error("execution_report_binding")


def _validate_denial(payload: bytes, *, before: bytes, after: bytes, final: bytes) -> None:
    value = _decode_json(payload, role="approval_denial")
    error = value.get("error")
    if (
        set(value) != {"error"}
        or not isinstance(error, dict)
        or set(error) != {"code", "context", "message", "remediation", "severity"}
        or error.get("code") != "APPROVAL_REQUIRED"
        or error.get("severity") != "blocking"
        or before != after
        or len(final) <= len(after)
        or not final.startswith(after)
    ):
        raise _validation_error("approval_denial")


def _validate_health(
    probe_payload: bytes,
    executor_payload: bytes,
    *,
    candidate: ReleaseCandidate,
    profile: ExecutionProfile,
    profile_hash: str,
) -> None:
    probe = _decode_json_line(probe_payload, role="probe_health")
    executor = _decode_json_line(executor_payload, role="executor_health")
    probe_result = _successful_health_result(probe, request_id="real-host-probe-health")
    executor_result = _successful_health_result(executor, request_id="real-host-executor-health")
    if (
        probe_result.get("operation") != "health"
        or probe_result.get("status") != "ok"
        or probe_result.get("protocol_version") != "1.0"
        or probe_result.get("probe_version") != candidate.probe_version
        or executor_result.get("status") != "ok"
        or executor_result.get("protocol_version") != "1.0"
        or executor_result.get("agent_version") != candidate.remote_executor_version
        or executor_result.get("profile_id") != profile.profile_id
        or executor_result.get("profile_hash") != profile_hash
    ):
        raise _validation_error("force_command_health")


def _successful_health_result(value: dict[str, Any], *, request_id: str) -> dict[str, Any]:
    if (
        set(value)
        != {
            "error",
            "protocol_version",
            "request_id",
            "result",
            "return_code",
            "success",
        }
        or value.get("protocol_version") != "1.0"
        or value.get("request_id") != request_id
        or value.get("success") is not True
        or value.get("return_code") != 0
        or value.get("error") is not None
        or not isinstance(value.get("result"), dict)
    ):
        raise _validation_error("health_envelope")
    return cast(dict[str, Any], value["result"])


def _validate_multiqc(
    report: bytes,
    data: bytes,
    *,
    report_path: Path,
    data_path: Path,
    run: RunReport,
) -> None:
    result_root = Path(run.result_dir)
    expected_report = result_root / "multiqc" / "multiqc_report.html"
    expected_data = result_root / "multiqc" / "multiqc_data" / "multiqc_data.json"
    if (
        Path(os.path.abspath(os.fspath(report_path))) != expected_report
        or Path(os.path.abspath(os.fspath(data_path))) != expected_data
    ):
        raise _validation_error("multiqc_path_binding")
    prefix = report[: 64 * 1024].lstrip().lower()
    if not (
        (prefix.startswith(b"<!doctype html") or prefix.startswith(b"<html"))
        and b"multiqc" in prefix
    ):
        raise _validation_error("multiqc_report")
    value = _decode_json(data, role="multiqc_data")
    general_stats = value.get("report_general_stats_data")
    if (
        not isinstance(general_stats, dict)
        or not general_stats
        or not all(isinstance(item, dict) and item for item in general_stats.values())
    ):
        raise _validation_error("multiqc_data")


def _validate_audit(
    payload: bytes,
    *,
    run: RunReport,
    status: StatusReport,
    preflight: PreflightReport,
    validation_sha256: str,
    test_sha256: str,
    preflight_sha256: str,
    created: datetime,
) -> None:
    events = _decode_audit(payload)
    relevant = [event for event in events if event.event_type in _RUNTIME_AUDIT_TYPES]
    event_types = [event.event_type for event in relevant]
    if (
        len(event_types) < 6
        or event_types[:4] != list(_AUDIT_SEQUENCE[:4])
        or event_types[-1] != "RUN_COMPLETED"
        or any(event_type != "RUN_STATUS_QUERIED" for event_type in event_types[4:-1])
    ):
        raise _validation_error("audit_sequence")
    if (
        any(event.status != _AUDIT_STATUS[event.event_type] for event in relevant)
        or any(event.project_id != run.project_id for event in relevant)
        or len({event.actor for event in relevant}) != 1
    ):
        raise _validation_error("audit_identity")

    submitted_time = _aware_utc(run.submitted_at, role="run_submitted_at")
    status_time = _aware_utc(status.checked_at, role="status_checked_at")
    event_times = [_aware_utc(event.timestamp, role="audit_timestamp") for event in relevant]
    if (
        event_times[0] < submitted_time
        or event_times[-2] < status_time
        or event_times[-1] < status_time
        or event_times[-1].replace(microsecond=0) > created
    ):
        raise _validation_error("audit_time_binding")

    expected_inputs = {
        **preflight.artifact_hashes.model_dump(mode="python"),
        "bundle": run.bundle_hash,
        "preflight_report": preflight_sha256,
        "test_report": test_sha256,
        "validation_report": validation_sha256,
    }
    if any(event.input_hashes != expected_inputs for event in relevant):
        raise _validation_error("audit_authorization_binding")
    run_id_hash = _sha256(run.run_id.encode("ascii"))
    run_reference = {run.run_id: run_id_hash}
    submitted = next(event for event in relevant if event.event_type == "RUN_SUBMITTED")
    completed = next(event for event in relevant if event.event_type == "RUN_COMPLETED")
    expected_outputs = {
        "REAL_DATA_APPROVED": {},
        "PIPELINE_DEPLOYED": {"bundle": run.bundle_hash},
        "RUN_SUBMISSION_STARTED": run_reference,
        "RUN_SUBMITTED": {
            "bundle": run.bundle_hash,
            "command": run.command_hash,
            "environment": run.environment_hash,
            **run_reference,
        },
        "RUN_STATUS_QUERIED": run_reference,
        "RUN_COMPLETED": {
            "command": status.command_hash,
            "environment": status.environment_hash,
            "return_code": _sha256(b"0"),
            **run_reference,
        },
    }
    if (
        any(event.output_hashes != expected_outputs[event.event_type] for event in relevant)
        or submitted.output_hashes != expected_outputs["RUN_SUBMITTED"]
        or completed.output_hashes != expected_outputs["RUN_COMPLETED"]
    ):
        raise _validation_error("audit_terminal_binding")


def _decode_audit(payload: bytes) -> tuple[AuditEvent, ...]:
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise _validation_error("audit_jsonl")
    lines = payload.splitlines()
    if not 1 <= len(lines) <= 10_000:
        raise _validation_error("audit_jsonl")
    events: list[AuditEvent] = []
    try:
        for line in lines:
            events.append(AuditEvent.model_validate(_decode_json(line, role="audit_event")))
    except (ValidationError, ValueError) as exc:
        raise _validation_error("audit_event") from exc
    if len({event.event_id for event in events}) != len(events) or any(
        first.timestamp > second.timestamp for first, second in pairwise(events)
    ):
        raise _validation_error("audit_order")
    return tuple(events)


def _validate_summary(value: dict[str, Any]) -> None:
    expected_keys = {
        "acceptance_format_version",
        "acceptance_status",
        "artifacts",
        "checks",
        "container_engine",
        "created_at",
        "data_classification",
        "evidence_status",
        "independent_review_status",
        "limitations",
        "network_claim",
        "preflight_check_count",
        "real_container_runtime_exercised",
        "real_remote_host_exercised",
        "real_ssh_exercised",
        "release_decision",
        "release_id",
        "source_git_commit",
        "synthetic_remote_only",
    }
    artifacts = value.get("artifacts")
    if (
        set(value) != expected_keys
        or value.get("acceptance_format_version") != "1.0"
        or value.get("acceptance_status") != "passed"
        or value.get("checks") != _CHECKS
        or value.get("container_engine") not in {"apptainer", "docker"}
        or value.get("data_classification") != "anonymous_synthetic_only"
        or value.get("evidence_status") != "OPERATOR_GENERATED_UNREVIEWED"
        or value.get("independent_review_status") != "PENDING_INDEPENDENT_REVIEW"
        or value.get("limitations") != list(_LIMITATIONS)
        or value.get("network_claim") != "remote_preflight_policy_passed_not_egress_attestation"
        or type(value.get("preflight_check_count")) is not int
        or not 10 <= value["preflight_check_count"] <= 12
        or value.get("real_container_runtime_exercised") is not True
        or value.get("real_remote_host_exercised") is not True
        or value.get("real_ssh_exercised") is not True
        or value.get("release_decision") != "BLOCKED"
        or value.get("synthetic_remote_only") is not True
        or not isinstance(value.get("release_id"), str)
        or _RELEASE_ID.fullmatch(value["release_id"]) is None
        or not isinstance(value.get("source_git_commit"), str)
        or _COMMIT.fullmatch(value["source_git_commit"]) is None
        or not isinstance(value.get("created_at"), str)
        or not isinstance(artifacts, dict)
        or frozenset(artifacts) != _ARTIFACT_NAMES
        or any(
            not isinstance(item, str) or _SHA256.fullmatch(item) is None
            for item in artifacts.values()
        )
    ):
        raise _validation_error("summary_schema")
    _canonical_time(cast(str, value["created_at"]), role="created_at")


def _decode_json(payload: bytes, *, role: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _validation_error(role) from exc
    if not isinstance(value, dict):
        raise _validation_error(role)
    return cast(dict[str, Any], value)


def _decode_json_line(payload: bytes, *, role: str) -> dict[str, Any]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1 or b"\r" in payload:
        raise _validation_error(role)
    return _decode_json(payload, role=role)


def _render_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _canonical_time(value: str, *, role: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise _validation_error(role) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise _validation_error(role)
    return parsed


def _aware_utc(value: datetime, *, role: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _validation_error(role)
    return value.astimezone(UTC)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _assert_sanitized(
    payload: bytes,
    *,
    repository: Path,
    candidate_evidence: Path,
    output_directory: Path,
    inputs: RealHostEvidenceInputs,
) -> None:
    forbidden = (
        b"/Users/",
        b"/home/",
        b"file://",
        b"PRIVATE KEY",
        b"Authorization:",
        b"Bearer ",
        b"approval.key",
        b".fastq",
        b".fq",
    )
    paths = (
        repository,
        candidate_evidence,
        output_directory,
        *(getattr(inputs, field.name) for field in fields(inputs)),
    )
    fragments = tuple(
        os.fsencode(path.absolute()) for path in paths if len(os.fspath(path.absolute())) >= 4
    )
    if any(marker in payload for marker in forbidden) or any(
        fragment in payload for fragment in fragments
    ):
        raise _validation_error("sanitized_output")


def _open_directory_no_symlink(directory: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(directory)))
    parts = absolute.parts
    if (
        not parts
        or not absolute.is_absolute()
        or any(component in {"", ".", ".."} for component in parts[1:])
    ):
        raise OSError("invalid evidence directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(parts[0], flags)
    try:
        for component in parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_evidence_directory(root: Path) -> dict[str, bytes]:
    descriptor: int | None = None
    try:
        descriptor = _open_directory_no_symlink(root)
        if frozenset(os.listdir(descriptor)) != REAL_HOST_EVIDENCE_NAMES:
            raise OSError("unexpected evidence file set")
        payloads: dict[str, bytes] = {}
        for name in sorted(REAL_HOST_EVIDENCE_NAMES):
            file_descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=descriptor,
            )
            try:
                before = os.fstat(file_descriptor)
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_INPUT_BYTES:
                    raise OSError("unsafe evidence file")
                payload = bytearray()
                while chunk := os.read(
                    file_descriptor,
                    min(1024 * 1024, _MAX_INPUT_BYTES + 1 - len(payload)),
                ):
                    payload.extend(chunk)
                    if len(payload) > _MAX_INPUT_BYTES:
                        raise OSError("evidence file exceeds limit")
                after = os.fstat(file_descriptor)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if len(payload) != before.st_size or any(
                    getattr(before, field) != getattr(after, field) for field in stable_fields
                ):
                    raise OSError("evidence file changed")
                payloads[name] = bytes(payload)
            finally:
                os.close(file_descriptor)
        if frozenset(os.listdir(descriptor)) != REAL_HOST_EVIDENCE_NAMES:
            raise OSError("evidence directory changed")
        return payloads
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "Real-host acceptance evidence is missing, unsafe, or incomplete.",
            remediation=["Use the exact create-only real-host evidence bundle."],
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validation_error(reason: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "Real-host acceptance evidence did not satisfy the reviewed format.",
        context={"reason": reason},
        remediation=["Preserve the private run records and repeat the failed operator step."],
    )


__all__ = [
    "REAL_HOST_EVIDENCE_NAMES",
    "RealHostEvidenceInputs",
    "create_real_host_acceptance_evidence",
    "verify_real_host_acceptance_evidence",
]
