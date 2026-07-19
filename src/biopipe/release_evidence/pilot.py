"""Compile a privacy-safe operator pilot record into reviewable evidence.

The compiler deliberately does not crawl generated projects, reports, audit
logs, private state, or remote hosts.  It validates only a strict sanitized
record, binds that record to existing M6.1 evidence and a clean source commit,
and publishes an explicitly unreviewed create-only bundle.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import unicodedata
from contextlib import suppress
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution import CoreArtifactHashes, compute_project_hash
from biopipe.release_evidence.acceptance import verify_release_acceptance_evidence
from biopipe.release_evidence.checksums import (
    checksum_payloads,
    parse_checksum_manifest,
    read_bounded_regular,
)
from biopipe.release_evidence.generator import (
    resolve_clean_repository_commit,
    validate_runtime_repository_binding,
    verify_release_evidence,
)
from biopipe.release_evidence.models import ReleaseCandidate
from biopipe.release_evidence.real_host import verify_real_host_acceptance_evidence
from biopipe.release_evidence.store import EvidenceBundleStore

PILOT_SUMMARY_NAME: Final[str] = "internal-pilot-summary.json"
PILOT_REPORT_NAME: Final[str] = "internal-pilot-review-draft.md"
PILOT_EVIDENCE_NAMES: Final[frozenset[str]] = frozenset(
    {PILOT_SUMMARY_NAME, PILOT_REPORT_NAME, "SHA256SUMS"}
)
_CORE_NAMES: Final[frozenset[str]] = PILOT_EVIDENCE_NAMES - {"SHA256SUMS"}
_MAX_INPUT_BYTES: Final[int] = 256 * 1024
_MAX_EVIDENCE_BYTES: Final[int] = 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 2 * 1024 * 1024

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_RELEASE_ID_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+-rc[1-9][0-9]*$"
_SEMVER_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+$"
_CONTRACT_PATTERN = r"^[0-9]+\.[0-9]+$"
_PILOT_ID_PATTERN = r"^pilot-[0-9]{8}-[0-9]{3}$"
_ENVIRONMENT_ID_PATTERN = r"^env-[0-9]{3}$"
_CASE_ID_PATTERN = r"^case-[0-9]{3}$"
_DRILL_ID_PATTERN = r"^drill-[0-9]{3}$"
_FRICTION_ID_PATTERN = r"^friction-[0-9]{3}$"
_ACTION_ID_PATTERN = r"^action-[0-9]{3}$"

_REQUIRED_CASE_SCENARIOS: Final[tuple[str, ...]] = (
    "plain_fastq_single_end",
    "gzip_paired_end",
    "paired_end_multi_lane",
    "missing_mate",
    "ambiguous_naming",
    "synthetic_execution_failure",
)
_SUCCESS_SCENARIOS: Final[frozenset[str]] = frozenset(_REQUIRED_CASE_SCENARIOS[:3])
_OWNER_ROLES: Final[tuple[str, ...]] = (
    "backup",
    "capacity",
    "incident",
    "key_rotation",
    "retention",
)
_FIXED_CODES: Final[frozenset[str]] = frozenset(
    {
        "NONE",
        "NOT_OBSERVED",
        "EVIDENCE_MISSING",
        "APPROVAL_REQUIRED",
        "COMMAND_TIMEOUT",
        "DEPLOYMENT_FAILED",
        "E2E_RUN_FAILED",
        "IMAGE_UNAVAILABLE",
        "INCOMPLETE_PAIRING",
        "INSUFFICIENT_SPACE",
        "MANIFEST_INTEGRITY_FAILED",
        "MANIFEST_OVERRIDE_CONFLICT",
        "MISSING_MATE",
        "NAMING_CONFLICT",
        "NF_TEST_FAILED",
        "PATH_OUTPUT_CONFLICT",
        "PATH_OUTSIDE_ALLOWLIST",
        "PATH_UNAVAILABLE",
        "PREFLIGHT_FAILED",
        "PREFLIGHT_STALE",
        "PROBE_REMOTE_FAILED",
        "RUN_FAILED",
        "RUN_STATUS_FAILED",
        "RUN_SUBMISSION_FAILED",
        "SSH_CONNECTION_FAILED",
        "SSH_HOST_KEY_MISMATCH",
        "SSH_TIMEOUT",
        "TARGET_ALREADY_EXISTS",
        "TOOL_NOT_FOUND",
        "UNTRUSTED_PATH_PERMISSIONS",
        "VALIDATION_FAILED",
    }
)
_DRILL_CODES: Final[dict[str, frozenset[str]]] = {
    "host_key_mismatch": frozenset({"SSH_HOST_KEY_MISMATCH"}),
    "source_unreachable": frozenset({"SSH_CONNECTION_FAILED", "SSH_TIMEOUT"}),
    "path_outside_allowlist": frozenset(
        {"PATH_OUTSIDE_ALLOWLIST", "PROBE_REMOTE_FAILED", "VALIDATION_FAILED"}
    ),
    "unsafe_writable_input": frozenset({"PREFLIGHT_FAILED", "UNTRUSTED_PATH_PERMISSIONS"}),
    "container_unavailable": frozenset(
        {"IMAGE_UNAVAILABLE", "PATH_UNAVAILABLE", "PREFLIGHT_FAILED"}
    ),
    "existing_output": frozenset(
        {"DEPLOYMENT_FAILED", "PATH_OUTPUT_CONFLICT", "TARGET_ALREADY_EXISTS"}
    ),
    "stale_preflight": frozenset({"PREFLIGHT_STALE"}),
    "approval_omitted": frozenset({"APPROVAL_REQUIRED"}),
    "lost_submit_response": frozenset(
        {"RUN_SUBMISSION_FAILED", "SSH_TIMEOUT", "SSH_CONNECTION_FAILED"}
    ),
    "low_disk_space": frozenset({"INSUFFICIENT_SPACE", "PREFLIGHT_FAILED"}),
}
_LIMITATIONS: Final[tuple[str, ...]] = (
    "operator_recorded_observations_not_source_evidence_verification",
    "independent_runs_not_verified_by_collector",
    "latest_reports_and_audit_history_not_read",
    "project_artifacts_and_private_state_not_read",
    "pilot_execution_and_failure_drills_not_performed_by_collector",
    "bundle_integrity_does_not_establish_authenticity_or_signoff",
    "production_use_not_authorized",
)

GateStatus = Literal["not_observed", "passed", "blocked", "failed", "evidence_missing"]
CheckStatus = Literal["not_performed", "passed", "failed", "evidence_missing"]
UsageBucket = Literal[
    "not_observed",
    "under_1_gib",
    "1_to_10_gib",
    "10_to_100_gib",
    "100_gib_to_1_tib",
    "at_least_1_tib",
]
CaseScenario = Literal[
    "plain_fastq_single_end",
    "gzip_paired_end",
    "paired_end_multi_lane",
    "missing_mate",
    "ambiguous_naming",
    "synthetic_execution_failure",
]
CaseState = Literal[
    "unexecuted",
    "evidence_missing",
    "succeeded",
    "blocked",
    "resolved",
    "failed_queryable",
    "failed",
]
DataClassification = Literal[
    "synthetic",
    "public_approved_non_sensitive",
    "organization_approved_non_sensitive",
]


class _StrictPilotModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _parse_canonical_utc(value: str, *, role: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError(f"{role} must use canonical UTC whole-second syntax") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError(f"{role} must use canonical UTC whole-second syntax")
    return parsed


def _require_fixed_code(value: str) -> str:
    if value not in _FIXED_CODES:
        raise ValueError("observation code is not in the reviewed allowlist")
    return value


class GateObservation(_StrictPilotModel):
    """One operator-recorded gate result without report content."""

    status: GateStatus
    code: str

    @field_validator("code")
    @classmethod
    def _code_is_allowlisted(cls, value: str) -> str:
        return _require_fixed_code(value)

    @model_validator(mode="after")
    def _status_matches_code(self) -> GateObservation:
        if self.status == "passed" and self.code != "NONE":
            raise ValueError("a passed gate must use NONE")
        if self.status == "not_observed" and self.code != "NOT_OBSERVED":
            raise ValueError("an unobserved gate must use NOT_OBSERVED")
        if self.status == "evidence_missing" and self.code != "EVIDENCE_MISSING":
            raise ValueError("a missing-evidence gate must use EVIDENCE_MISSING")
        if self.status in {"blocked", "failed"} and self.code in {
            "NONE",
            "NOT_OBSERVED",
            "EVIDENCE_MISSING",
        }:
            raise ValueError("a blocked or failed gate requires a stable failure code")
        return self


class AuditObservation(_StrictPilotModel):
    """Operator-recorded audit checks; the collector never reads audit lines."""

    parse_status: CheckStatus
    order_status: CheckStatus
    authorization_binding_status: CheckStatus
    terminal_binding_status: CheckStatus

    def all_passed(self) -> bool:
        return all(
            status == "passed"
            for status in (
                self.parse_status,
                self.order_status,
                self.authorization_binding_status,
                self.terminal_binding_status,
            )
        )

    def not_performed(self) -> bool:
        return all(
            status == "not_performed"
            for status in (
                self.parse_status,
                self.order_status,
                self.authorization_binding_status,
                self.terminal_binding_status,
            )
        )


class RunTransition(_StrictPilotModel):
    status: Literal["pending", "running", "succeeded", "failed"]
    observed_at: str
    return_code: int | None = Field(default=None, ge=0, le=255)

    @field_validator("observed_at")
    @classmethod
    def _time_is_canonical(cls, value: str) -> str:
        _parse_canonical_utc(value, role="run transition time")
        return value

    @model_validator(mode="after")
    def _return_code_matches_status(self) -> RunTransition:
        if self.status in {"pending", "running"} and self.return_code is not None:
            raise ValueError("a non-terminal run transition cannot include a return code")
        if self.status == "succeeded" and self.return_code != 0:
            raise ValueError("a succeeded run transition must have return code zero")
        if self.status == "failed" and (self.return_code is None or self.return_code == 0):
            raise ValueError("a failed run transition requires a nonzero return code")
        return self


class CaseHashes(_StrictPilotModel):
    """Fixed-role pointers to controlled evidence; no source path is accepted."""

    dataset_manifest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    pipeline_spec: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    execution_plan: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    software_lock: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    execution_profile: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    validation_report: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    test_report: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    preflight_report: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    run_report: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    status_report: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    audit: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    project_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    bundle_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    command_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    environment_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _project_hash_is_internally_consistent(self) -> CaseHashes:
        core = (
            self.dataset_manifest,
            self.pipeline_spec,
            self.execution_plan,
            self.software_lock,
            self.execution_profile,
        )
        present = sum(value is not None for value in core)
        if present == len(core):
            assert all(value is not None for value in core)
            observed = compute_project_hash(
                CoreArtifactHashes(
                    dataset_manifest=cast(str, self.dataset_manifest),
                    pipeline_spec=cast(str, self.pipeline_spec),
                    execution_plan=cast(str, self.execution_plan),
                    software_lock=cast(str, self.software_lock),
                    execution_profile=cast(str, self.execution_profile),
                )
            )
            if self.project_hash != observed:
                raise ValueError("project hash does not match the recorded core artifact hashes")
        elif self.project_hash is not None:
            raise ValueError("project hash requires all five core artifact hashes")
        return self

    def has_complete_execution_evidence(self) -> bool:
        return all(
            getattr(self, name) is not None
            for name in (
                "dataset_manifest",
                "pipeline_spec",
                "execution_plan",
                "software_lock",
                "execution_profile",
                "validation_report",
                "test_report",
                "preflight_report",
                "run_report",
                "status_report",
                "audit",
                "project_hash",
                "bundle_hash",
                "command_hash",
                "environment_hash",
            )
        )


class PilotCase(_StrictPilotModel):
    case_id: str = Field(pattern=_CASE_ID_PATTERN)
    scenario: CaseScenario
    state: CaseState
    data_classification: DataClassification
    observed_at: str | None = None
    scan_file_count: int | None = Field(default=None, ge=0, le=1_000_000)
    scan_duration_ms: int | None = Field(default=None, ge=0, le=86_400_000)
    manifest_sample_count: int | None = Field(default=None, ge=0, le=100_000)
    manifest_lane_count: int | None = Field(default=None, ge=0, le=1_000_000)
    validation: GateObservation
    test: GateObservation
    preflight: GateObservation
    run_transitions: list[RunTransition] = Field(default_factory=list, max_length=8)
    work_usage_bucket: UsageBucket
    output_usage_bucket: UsageBucket
    external_command_timeout_count: int = Field(ge=0, le=1000)
    external_command_error_codes: list[str] = Field(default_factory=list, max_length=16)
    reported_audit: AuditObservation
    hashes: CaseHashes
    run_id_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    attribution_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    controlled_evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def _observed_time_is_canonical(cls, value: str | None) -> str | None:
        if value is not None:
            _parse_canonical_utc(value, role="case observation time")
        return value

    @field_validator("external_command_error_codes")
    @classmethod
    def _external_codes_are_allowlisted(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("external command error codes must be unique")
        normalized = [_require_fixed_code(value) for value in values]
        if any(value in {"NONE", "NOT_OBSERVED", "EVIDENCE_MISSING"} for value in normalized):
            raise ValueError("external command error codes cannot use non-error sentinels")
        return normalized

    @model_validator(mode="after")
    def _case_state_is_honest(self) -> PilotCase:
        if (
            self.manifest_sample_count is not None
            and self.manifest_lane_count is not None
            and self.manifest_lane_count < self.manifest_sample_count
        ):
            raise ValueError("manifest lane count cannot be smaller than sample count")

        if self.run_transitions:
            ranks = {"pending": 0, "running": 1, "succeeded": 2, "failed": 2}
            observed_ranks = [ranks[item.status] for item in self.run_transitions]
            if observed_ranks != sorted(observed_ranks):
                raise ValueError("run transitions must be monotonic")
            if len({item.status for item in self.run_transitions}) != len(self.run_transitions):
                raise ValueError("run transition statuses must be unique")
            if sum(item.status in {"succeeded", "failed"} for item in self.run_transitions) != 1:
                raise ValueError(
                    "a run transition sequence must contain exactly one terminal state"
                )
            if any(
                first.observed_at >= second.observed_at
                for first, second in zip(
                    self.run_transitions, self.run_transitions[1:], strict=False
                )
            ):
                raise ValueError("run transition times must increase")
            if self.run_transitions[-1].status not in {"succeeded", "failed"}:
                raise ValueError("a recorded run transition sequence must be terminal")

        if self.state == "unexecuted":
            if any(
                value is not None
                for value in (
                    self.observed_at,
                    self.scan_file_count,
                    self.scan_duration_ms,
                    self.manifest_sample_count,
                    self.manifest_lane_count,
                    self.run_id_sha256,
                    self.attribution_record_sha256,
                    self.controlled_evidence_sha256,
                )
            ) or any(
                (
                    self.validation.status != "not_observed",
                    self.test.status != "not_observed",
                    self.preflight.status != "not_observed",
                    bool(self.run_transitions),
                    self.work_usage_bucket != "not_observed",
                    self.output_usage_bucket != "not_observed",
                    self.external_command_timeout_count != 0,
                    bool(self.external_command_error_codes),
                    not self.reported_audit.not_performed(),
                    any(value is not None for value in self.hashes.model_dump().values()),
                )
            ):
                raise ValueError("an unexecuted case cannot contain observed facts")
            return self

        if self.observed_at is None:
            raise ValueError("an observed case requires an observation time")
        if self.state != "evidence_missing" and self.controlled_evidence_sha256 is None:
            raise ValueError("an observed case requires a controlled evidence digest")
        if self.state == "succeeded":
            if self.scenario not in _SUCCESS_SCENARIOS:
                raise ValueError("only the three execution scenarios may be marked succeeded")
            if any(
                gate.status != "passed" for gate in (self.validation, self.test, self.preflight)
            ):
                raise ValueError("a succeeded case requires all three recorded gates to pass")
            if (
                not self.run_transitions
                or self.run_transitions[-1].status != "succeeded"
                or not self.reported_audit.all_passed()
                or not self.hashes.has_complete_execution_evidence()
                or any(
                    value is None
                    for value in (
                        self.scan_file_count,
                        self.scan_duration_ms,
                        self.manifest_sample_count,
                        self.manifest_lane_count,
                        self.run_id_sha256,
                    )
                )
                or self.work_usage_bucket == "not_observed"
                or self.output_usage_bucket == "not_observed"
            ):
                raise ValueError("a succeeded case is missing required recorded evidence")
            observed_counts = (
                cast(int, self.scan_file_count),
                cast(int, self.scan_duration_ms),
                cast(int, self.manifest_sample_count),
                cast(int, self.manifest_lane_count),
            )
            if any(value <= 0 for value in observed_counts) or (
                self.scenario == "paired_end_multi_lane"
                and cast(int, self.manifest_lane_count) <= cast(int, self.manifest_sample_count)
            ):
                raise ValueError("a succeeded case requires positive scenario-consistent counts")
        elif self.state == "blocked":
            allowed_hashes = {"dataset_manifest", "validation_report"}
            if (
                self.scenario != "missing_mate"
                or self.validation.code
                not in {"MISSING_MATE", "INCOMPLETE_PAIRING", "VALIDATION_FAILED"}
                or self.test.status != "not_observed"
                or self.preflight.status != "not_observed"
                or self.run_id_sha256 is not None
                or self.attribution_record_sha256 is not None
                or self.work_usage_bucket != "not_observed"
                or self.output_usage_bucket != "not_observed"
                or not self.reported_audit.not_performed()
                or any(
                    value is not None and name not in allowed_hashes
                    for name, value in self.hashes.model_dump().items()
                )
            ):
                raise ValueError("the required blocked case must record the missing-mate code")
            if self.run_transitions:
                raise ValueError("the missing-mate case must remain blocked before execution")
        elif self.state == "resolved":
            if (
                self.scenario != "ambiguous_naming"
                or self.attribution_record_sha256 is None
                or self.run_transitions
                or self.validation.status != "passed"
                or self.hashes.dataset_manifest is None
                or self.test.status != "not_observed"
                or self.preflight.status != "not_observed"
                or self.run_id_sha256 is not None
                or self.work_usage_bucket != "not_observed"
                or self.output_usage_bucket != "not_observed"
                or not self.reported_audit.not_performed()
                or any(
                    value is not None and name != "dataset_manifest"
                    for name, value in self.hashes.model_dump().items()
                )
            ):
                raise ValueError("the ambiguity case requires an attributable override digest")
        elif self.state == "failed_queryable":
            if (
                self.scenario != "synthetic_execution_failure"
                or self.data_classification != "synthetic"
                or any(
                    gate.status != "passed" for gate in (self.validation, self.test, self.preflight)
                )
                or not self.run_transitions
                or len(self.run_transitions) < 2
                or self.run_transitions[0].status != "pending"
                or self.run_transitions[-1].status != "failed"
                or self.run_id_sha256 is None
                or not self.hashes.has_complete_execution_evidence()
                or not self.reported_audit.all_passed()
                or self.work_usage_bucket == "not_observed"
                or self.output_usage_bucket == "not_observed"
                or any(
                    value is None or value <= 0
                    for value in (
                        self.scan_file_count,
                        self.scan_duration_ms,
                        self.manifest_sample_count,
                        self.manifest_lane_count,
                    )
                )
            ):
                raise ValueError("the synthetic failure must be terminal and queryable")
        elif self.state == "failed":
            if self.run_transitions and self.run_transitions[-1].status != "failed":
                raise ValueError("a failed case cannot record a succeeded terminal state")
        elif self.state == "evidence_missing" and self.run_transitions:
            raise ValueError("a missing-evidence case cannot assert a terminal run transition")
        if self.state in {"succeeded", "failed_queryable"} and (
            len(self.run_transitions) < 2 or self.run_transitions[0].status != "pending"
        ):
            raise ValueError("an executed case requires a pending-to-terminal transition")
        if (
            self.run_transitions
            and self.observed_at is not None
            and (self.observed_at < self.run_transitions[-1].observed_at)
        ):
            raise ValueError("case observation time cannot precede the terminal run state")
        return self


class PilotDrill(_StrictPilotModel):
    drill_id: str = Field(pattern=_DRILL_ID_PATTERN)
    drill_type: Literal[
        "host_key_mismatch",
        "source_unreachable",
        "path_outside_allowlist",
        "unsafe_writable_input",
        "container_unavailable",
        "existing_output",
        "stale_preflight",
        "approval_omitted",
        "lost_submit_response",
        "low_disk_space",
    ]
    state: Literal["unexecuted", "evidence_missing", "blocked_expected", "recovered", "failed"]
    expected_code: str
    observed_code: str
    observed_at: str | None = None
    control_relaxed: Literal[False]
    controlled_evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @field_validator("expected_code", "observed_code")
    @classmethod
    def _codes_are_allowlisted(cls, value: str) -> str:
        return _require_fixed_code(value)

    @field_validator("observed_at")
    @classmethod
    def _drill_time_is_canonical(cls, value: str | None) -> str | None:
        if value is not None:
            _parse_canonical_utc(value, role="drill observation time")
        return value

    @model_validator(mode="after")
    def _drill_state_is_honest(self) -> PilotDrill:
        allowed = _DRILL_CODES[self.drill_type]
        if self.expected_code not in allowed:
            raise ValueError("expected drill code does not match the drill type")
        if self.state == "unexecuted":
            if (
                self.observed_code != "NOT_OBSERVED"
                or self.observed_at is not None
                or self.controlled_evidence_sha256 is not None
            ):
                raise ValueError("an unexecuted drill cannot contain observed evidence")
        elif self.state == "evidence_missing":
            if self.observed_code != "EVIDENCE_MISSING" or self.observed_at is None:
                raise ValueError("a missing-evidence drill requires its explicit stable state")
        else:
            if (
                self.observed_code not in allowed
                or self.observed_at is None
                or self.controlled_evidence_sha256 is None
            ):
                raise ValueError("an executed drill requires matching code, time, and evidence")
        return self


class OwnerAssignment(_StrictPilotModel):
    role: Literal["backup", "capacity", "incident", "key_rotation", "retention"]
    status: Literal["pending", "recorded_in_restricted_system"]
    restricted_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _assignment_has_private_binding(self) -> OwnerAssignment:
        if (self.status == "recorded_in_restricted_system") != (
            self.restricted_record_sha256 is not None
        ):
            raise ValueError("owner assignment status must match its restricted record digest")
        return self


class CapacityRetentionObservation(_StrictPilotModel):
    deploy_usage_bucket: UsageBucket
    work_usage_bucket: UsageBucket
    output_usage_bucket: UsageBucket
    cache_usage_bucket: UsageBucket
    capacity_decision: Literal["pending", "approved", "blocked"]
    retention_decision: Literal["pending", "approved", "hold"]
    restricted_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _decision_has_private_binding(self) -> CapacityRetentionObservation:
        decided = self.capacity_decision != "pending" or self.retention_decision != "pending"
        if decided != (self.restricted_record_sha256 is not None):
            raise ValueError(
                "capacity and retention decisions require one restricted record digest"
            )
        if (
            self.capacity_decision == "approved"
            and self.retention_decision in {"approved", "hold"}
            and "not_observed"
            in {
                self.deploy_usage_bucket,
                self.work_usage_bucket,
                self.output_usage_bucket,
                self.cache_usage_bucket,
            }
        ):
            raise ValueError("approved decisions require every capacity usage bucket")
        return self


class BackupRestoreObservation(_StrictPilotModel):
    status: Literal["not_run", "passed", "failed"]
    restricted_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _restore_has_private_binding(self) -> BackupRestoreObservation:
        if (self.status != "not_run") != (self.restricted_record_sha256 is not None):
            raise ValueError("an observed backup restore requires a restricted record digest")
        return self


class DocumentationOperationObservation(_StrictPilotModel):
    result: Literal[
        "not_observed", "completed_with_assistance", "completed_from_documentation_only"
    ]
    restricted_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _operation_has_private_binding(self) -> DocumentationOperationObservation:
        if (self.result != "not_observed") != (self.restricted_record_sha256 is not None):
            raise ValueError("an observed documentation-only operation requires a record digest")
        return self


class FrictionRecord(_StrictPilotModel):
    friction_id: str = Field(pattern=_FRICTION_ID_PATTERN)
    step: Literal[
        "entry_gate",
        "deployment",
        "inspection",
        "manifest",
        "planning",
        "generation",
        "validation",
        "testing",
        "preflight",
        "approval",
        "submission",
        "status",
        "reconciliation",
        "audit",
        "capacity",
        "retention",
        "backup",
        "incident",
        "key_rotation",
    ]
    impact: Literal["low", "moderate", "blocking"]
    status: Literal["open", "resolved", "deferred"]
    action_id: str | None = Field(default=None, pattern=_ACTION_ID_PATTERN)

    @model_validator(mode="after")
    def _open_friction_has_action(self) -> FrictionRecord:
        if self.status != "resolved" and self.action_id is None:
            raise ValueError("unresolved friction requires a corrective action identifier")
        return self


class CorrectiveAction(_StrictPilotModel):
    action_id: str = Field(pattern=_ACTION_ID_PATTERN)
    friction_id: str = Field(pattern=_FRICTION_ID_PATTERN)
    owner_role: Literal[
        "pilot_owner",
        "data_owner",
        "runtime_owner",
        "security_owner",
        "backup_owner",
        "capacity_owner",
        "incident_owner",
        "key_rotation_owner",
        "retention_owner",
    ]
    priority: Literal["p0", "p1", "p2", "p3"]
    status: Literal["open", "completed", "deferred"]
    due_date: str
    verification_method: Literal[
        "automated_regression",
        "controlled_rerun",
        "runbook_review",
        "independent_evidence_review",
        "site_control_check",
    ]
    restricted_record_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("due_date")
    @classmethod
    def _due_date_is_canonical(cls, value: str) -> str:
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("action due date must use YYYY-MM-DD") from exc
        if parsed.isoformat() != value:
            raise ValueError("action due date must use YYYY-MM-DD")
        return value


class EntryGateRecord(_StrictPilotModel):
    status: Literal[
        "not_recorded",
        "recorded_pending_independent_review",
        "recorded_complete_in_restricted_system",
    ]
    restricted_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _entry_gate_has_private_binding(self) -> EntryGateRecord:
        if (self.status != "not_recorded") != (self.restricted_record_sha256 is not None):
            raise ValueError("entry-gate status must match its restricted record digest")
        return self


class ControlDeviation(_StrictPilotModel):
    status: Literal["none", "restricted_incident_recorded", "unresolved"]
    restricted_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _deviation_has_private_binding(self) -> ControlDeviation:
        if (self.status != "none") != (self.restricted_record_sha256 is not None):
            raise ValueError("a control deviation requires a restricted record digest")
        return self


class ExpectedEvidenceIdentity(_StrictPilotModel):
    release_id: str = Field(pattern=_RELEASE_ID_PATTERN)
    source_git_commit: str = Field(pattern=_COMMIT_PATTERN)
    candidate_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    release_acceptance_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    real_host_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)


class SanitizedPilotRecord(_StrictPilotModel):
    """The only operator input admitted into the lower-trust pilot bundle."""

    format_version: Literal["1.0"]
    collection_policy_version: Literal["1.0"]
    pilot_id: str = Field(pattern=_PILOT_ID_PATTERN)
    environment_id: str = Field(pattern=_ENVIRONMENT_ID_PATTERN)
    recorded_at: str
    data_boundary: Literal["non_sensitive_only"]
    expected_evidence: ExpectedEvidenceIdentity
    entry_gate: EntryGateRecord
    cases: list[PilotCase] = Field(min_length=6, max_length=6)
    drills: list[PilotDrill] = Field(default_factory=list, max_length=10)
    owner_assignments: list[OwnerAssignment] = Field(min_length=5, max_length=5)
    capacity_retention: CapacityRetentionObservation
    backup_restore: BackupRestoreObservation
    operator_documentation: DocumentationOperationObservation
    friction_review_status: Literal["not_recorded", "recorded_none", "recorded_with_findings"]
    friction: list[FrictionRecord] = Field(default_factory=list, max_length=64)
    corrective_actions: list[CorrectiveAction] = Field(default_factory=list, max_length=64)
    control_deviation: ControlDeviation
    controls_relaxed: Literal[False]
    next_recommendation: Literal["repeat_pilot", "remain_blocked", "request_independent_m62_review"]

    @field_validator("recorded_at")
    @classmethod
    def _recorded_time_is_canonical(cls, value: str) -> str:
        _parse_canonical_utc(value, role="pilot record time")
        return value

    @model_validator(mode="after")
    def _record_is_complete_and_unambiguous(self) -> SanitizedPilotRecord:
        if self.pilot_id[6:14] != self.recorded_at[:10].replace("-", ""):
            raise ValueError("pilot identifier date must match the record date")
        scenarios = [item.scenario for item in self.cases]
        if sorted(scenarios) != sorted(_REQUIRED_CASE_SCENARIOS):
            raise ValueError("the six required pilot case scenarios must each appear once")
        if len({item.case_id for item in self.cases}) != len(self.cases):
            raise ValueError("pilot case identifiers must be unique")
        if len({item.drill_id for item in self.drills}) != len(self.drills) or len(
            {item.drill_type for item in self.drills}
        ) != len(self.drills):
            raise ValueError("drill identifiers and types must be unique")
        roles = [item.role for item in self.owner_assignments]
        if sorted(roles) != list(_OWNER_ROLES):
            raise ValueError("all five operational owner roles must appear once")
        friction_ids = [item.friction_id for item in self.friction]
        action_ids = [item.action_id for item in self.corrective_actions]
        if len(set(friction_ids)) != len(friction_ids) or len(set(action_ids)) != len(action_ids):
            raise ValueError("friction and action identifiers must be unique")
        if (self.friction_review_status == "recorded_with_findings") != bool(self.friction) or (
            self.friction_review_status in {"not_recorded", "recorded_none"} and self.friction
        ):
            raise ValueError("friction review status must match the recorded finding set")
        action_by_id = {item.action_id: item for item in self.corrective_actions}
        friction_by_id = {item.friction_id: item for item in self.friction}
        if any(
            item.action_id is not None
            and (
                item.action_id not in action_by_id
                or action_by_id[item.action_id].friction_id != item.friction_id
            )
            for item in self.friction
        ) or any(
            item.friction_id not in friction_by_id
            or friction_by_id[item.friction_id].action_id != item.action_id
            for item in self.corrective_actions
        ):
            raise ValueError("corrective actions must bind exactly to known friction records")
        expected_action_status = {"open": "open", "resolved": "completed", "deferred": "deferred"}
        if any(
            item.action_id is not None
            and action_by_id[item.action_id].status != expected_action_status[item.status]
            for item in self.friction
        ):
            raise ValueError("friction and corrective action states must agree")

        recorded = _parse_canonical_utc(self.recorded_at, role="pilot record time")
        nested_times = [
            value
            for value in (
                *(item.observed_at for item in self.cases),
                *(
                    transition.observed_at
                    for item in self.cases
                    for transition in item.run_transitions
                ),
                *(item.observed_at for item in self.drills),
            )
            if value is not None
        ]
        if any(
            _parse_canonical_utc(value, role="nested observation time") > recorded
            for value in nested_times
        ):
            raise ValueError("pilot observations cannot be later than the record time")
        return self


class ReleaseIdentity(_StrictPilotModel):
    release_id: str = Field(pattern=_RELEASE_ID_PATTERN)
    source_git_commit: str = Field(pattern=_COMMIT_PATTERN)
    controller_version: str = Field(pattern=_SEMVER_PATTERN)
    probe_version: str = Field(pattern=_SEMVER_PATTERN)
    remote_executor_version: str = Field(pattern=_SEMVER_PATTERN)
    compiler_version: str = Field(pattern=_SEMVER_PATTERN)
    registry_version: str = Field(pattern=_SEMVER_PATTERN)
    schema_version: str = Field(pattern=_CONTRACT_PATTERN)
    cli_contract_version: str = Field(pattern=_CONTRACT_PATTERN)


class EvidenceBindings(_StrictPilotModel):
    candidate_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    release_acceptance_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    real_host_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_sanitized_record_sha256: str = Field(pattern=_SHA256_PATTERN)


class PilotCriteria(_StrictPilotModel):
    recorded_successful_case_count: int = Field(ge=0, le=3)
    recorded_recovered_drill_count: int = Field(ge=0, le=10)
    evidence_missing_case_count: int = Field(ge=0, le=6)
    unresolved_blocking_friction_count: int = Field(ge=0, le=64)
    required_case_outcomes_recorded: bool
    minimum_failure_drills_recorded: bool
    success_identity_hashes_unique: bool
    all_success_audit_checks_recorded_passed: bool
    operational_owners_recorded: bool
    capacity_and_retention_decisions_recorded: bool
    backup_restore_recorded_passed: bool
    documentation_only_operation_recorded: bool
    friction_review_recorded: bool
    entry_gate_recorded_complete: bool
    recorded_controls_remained_strict: Literal[True] = True
    criteria_state: Literal["INCOMPLETE_OR_BLOCKED", "READY_FOR_INDEPENDENT_REVIEW"]


class PilotSummary(_StrictPilotModel):
    pilot_evidence_format_version: Literal["1.0"] = "1.0"
    created_at: str
    release_identity: ReleaseIdentity
    evidence_bindings: EvidenceBindings
    sanitized_record: SanitizedPilotRecord
    criteria: PilotCriteria
    record_source: Literal["operator_supplied_sanitized"] = "operator_supplied_sanitized"
    record_state: Literal["OPERATOR_RECORDED_UNREVIEWED"] = "OPERATOR_RECORDED_UNREVIEWED"
    independent_review_status: Literal["PENDING_INDEPENDENT_REVIEW"] = "PENDING_INDEPENDENT_REVIEW"
    milestone_decision: Literal["BLOCKED"] = "BLOCKED"
    production_authorization: Literal[False] = False
    project_artifact_verification: Literal["not_performed_by_collector"] = (
        "not_performed_by_collector"
    )
    audit_semantic_verification: Literal["not_performed_by_collector"] = (
        "not_performed_by_collector"
    )
    project_tree_read: Literal[False] = False
    private_state_read: Literal[False] = False
    network_accessed: Literal[False] = False
    raw_content_exported: Literal[False] = False
    limitations: list[str]

    @field_validator("created_at")
    @classmethod
    def _created_time_is_canonical(cls, value: str) -> str:
        _parse_canonical_utc(value, role="pilot evidence creation time")
        return value

    @model_validator(mode="after")
    def _summary_is_self_consistent(self) -> PilotSummary:
        expected = self.sanitized_record.expected_evidence
        if (
            self.release_identity.release_id != expected.release_id
            or self.release_identity.source_git_commit != expected.source_git_commit
            or self.evidence_bindings.candidate_manifest_sha256
            != expected.candidate_manifest_sha256
            or self.evidence_bindings.release_acceptance_manifest_sha256
            != expected.release_acceptance_manifest_sha256
            or self.evidence_bindings.real_host_manifest_sha256
            != expected.real_host_manifest_sha256
            or self.evidence_bindings.normalized_sanitized_record_sha256
            != _sha256(_render_json(_normalized_record_dict(self.sanitized_record)))
            or self.sanitized_record.model_dump(mode="json")
            != _normalized_record_dict(self.sanitized_record)
            or self.criteria != _derive_criteria(self.sanitized_record)
            or self.limitations != list(_LIMITATIONS)
            or _parse_canonical_utc(self.created_at, role="pilot evidence creation time")
            < _parse_canonical_utc(self.sanitized_record.recorded_at, role="pilot record time")
        ):
            raise ValueError("pilot summary bindings or derived criteria are inconsistent")
        return self


class PilotEvidenceVerification(_StrictPilotModel):
    pilot_id: str = Field(pattern=_PILOT_ID_PATTERN)
    source_git_commit: str = Field(pattern=_COMMIT_PATTERN)
    criteria_state: Literal["INCOMPLETE_OR_BLOCKED", "READY_FOR_INDEPENDENT_REVIEW"]
    integrity_status: Literal["verified"] = "verified"
    independent_review_status: Literal["PENDING_INDEPENDENT_REVIEW"] = "PENDING_INDEPENDENT_REVIEW"
    milestone_decision: Literal["BLOCKED"] = "BLOCKED"
    evidence_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: Literal[3] = 3


def _require_private_paths_outside_repository(
    *,
    repository: Path,
    candidate_evidence: Path,
    release_acceptance_evidence: Path,
    real_host_evidence: Path,
    sanitized_record: Path,
    output_directory: Path,
) -> None:
    private_paths = (
        candidate_evidence,
        release_acceptance_evidence,
        real_host_evidence,
        sanitized_record,
        output_directory,
    )
    if any(_path_is_within(path, repository) for path in private_paths):
        raise _validation_error("private_path_inside_repository")
    repository_identity = _required_directory_identity(repository)
    if any(repository_identity in _existing_directory_identities(path) for path in private_paths):
        raise _validation_error("private_path_inside_repository")
    evidence_roots = (candidate_evidence, release_acceptance_evidence, real_host_evidence)
    if any(
        _path_is_within(output_directory, root) or _path_is_within(root, output_directory)
        for root in evidence_roots
    ):
        raise _validation_error("private_path_role_overlap")
    output_identities = _existing_directory_identities(output_directory)
    output_identity = _complete_directory_identity(output_directory)
    for root in evidence_roots:
        root_identities = _existing_directory_identities(root)
        root_identity = _required_directory_identity(root)
        if root_identity in output_identities or (
            output_identity is not None and output_identity in root_identities
        ):
            raise _validation_error("private_path_role_overlap")


def _path_is_within(candidate: Path, root: Path) -> bool:
    """Compare normalized path components conservatively across supported filesystems."""

    candidate_parts = tuple(
        unicodedata.normalize("NFD", part).casefold() for part in candidate.parts
    )
    root_parts = tuple(unicodedata.normalize("NFD", part).casefold() for part in root.parts)
    return (
        len(candidate_parts) >= len(root_parts) and candidate_parts[: len(root_parts)] == root_parts
    )


def _existing_directory_identity_chain(
    path: Path,
) -> tuple[tuple[tuple[int, int], ...], bool]:
    """Return no-follow identities for existing directory ancestors.

    macOS firmlinks and mounted aliases can expose one directory under multiple
    unrelated lexical paths.  Walking with directory descriptors preserves the
    existing no-symlink boundary while making those aliases comparable by
    filesystem identity.  ``complete`` is false for a regular-file leaf or the
    first missing/non-directory component.
    """

    parts = path.parts
    if not parts or not path.is_absolute():
        raise _validation_error("private_path_identity")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    identities: list[tuple[int, int]] = []
    try:
        descriptor = os.open(parts[0], flags)
        metadata = os.fstat(descriptor)
        identities.append((metadata.st_dev, metadata.st_ino))
        for component in parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
                    return tuple(identities), False
                raise
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            identities.append((metadata.st_dev, metadata.st_ino))
        return tuple(identities), True
    except OSError as exc:
        raise _validation_error("private_path_identity") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def _existing_directory_identities(path: Path) -> frozenset[tuple[int, int]]:
    identities, _complete = _existing_directory_identity_chain(path)
    return frozenset(identities)


def _complete_directory_identity(path: Path) -> tuple[int, int] | None:
    identities, complete = _existing_directory_identity_chain(path)
    return identities[-1] if complete else None


def _required_directory_identity(path: Path) -> tuple[int, int]:
    identity = _complete_directory_identity(path)
    if identity is None:
        raise _validation_error("private_path_identity")
    return identity


def _lexical_absolute(path: str | Path, *, role: str) -> Path:
    raw = os.fspath(path)
    if not raw or "\x00" in raw or raw.startswith("//"):
        raise _validation_error(role)
    return Path(os.path.abspath(raw))


def create_pilot_evidence(
    *,
    repository: str | Path,
    candidate_evidence: str | Path,
    release_acceptance_evidence: str | Path,
    real_host_evidence: str | Path,
    sanitized_record: str | Path,
    output_directory: str | Path,
    created_at: str,
) -> PilotEvidenceVerification:
    """Create one blocked, unreviewed, privacy-safe internal-pilot bundle."""

    try:
        created = _parse_canonical_utc(created_at, role="pilot evidence creation time")
    except ValueError as exc:
        raise _validation_error("created_at") from exc
    repository_path = _lexical_absolute(repository, role="repository_path")
    candidate_root = _lexical_absolute(candidate_evidence, role="candidate_evidence_path")
    acceptance_root = _lexical_absolute(
        release_acceptance_evidence, role="release_acceptance_evidence_path"
    )
    real_host_root = _lexical_absolute(real_host_evidence, role="real_host_evidence_path")
    record_path = _lexical_absolute(sanitized_record, role="sanitized_record_path")
    output_path = _lexical_absolute(output_directory, role="output_directory_path")
    _require_private_paths_outside_repository(
        repository=repository_path,
        candidate_evidence=candidate_root,
        release_acceptance_evidence=acceptance_root,
        real_host_evidence=real_host_root,
        sanitized_record=record_path,
        output_directory=output_path,
    )
    record_payload = read_bounded_regular(
        record_path,
        role="sanitized_pilot_record",
        limit_bytes=_MAX_INPUT_BYTES,
    )
    record = _load_model(record_payload, SanitizedPilotRecord, role="sanitized_pilot_record")
    if created < _parse_canonical_utc(record.recorded_at, role="pilot record time"):
        raise _validation_error("created_at")
    normalized_record_payload = _render_json(_normalized_record_dict(record))
    normalized_record = _load_model(
        normalized_record_payload,
        SanitizedPilotRecord,
        role="normalized_sanitized_pilot_record",
    )

    candidate_verification = verify_release_evidence(candidate_root)
    candidate_payload = read_bounded_regular(
        candidate_root / "candidate.json",
        role="candidate_record",
        limit_bytes=_MAX_EVIDENCE_BYTES,
    )
    candidate = _load_model(candidate_payload, ReleaseCandidate, role="candidate_record")
    second_candidate_verification = verify_release_evidence(candidate_root)
    if candidate_verification != second_candidate_verification:
        raise _validation_error("candidate_evidence_changed")

    acceptance_verification = verify_release_acceptance_evidence(acceptance_root)
    real_host_verification = verify_real_host_acceptance_evidence(real_host_root)
    expected = normalized_record.expected_evidence
    if (
        candidate.release_id != candidate_verification.release_id
        or candidate.git_commit != candidate_verification.git_commit
        or expected.release_id != candidate.release_id
        or expected.source_git_commit != candidate.git_commit
        or expected.candidate_manifest_sha256 != candidate_verification.evidence_manifest_sha256
        or acceptance_verification.get("release_id") != candidate.release_id
        or acceptance_verification.get("source_git_commit") != candidate.git_commit
        or acceptance_verification.get("evidence_manifest_sha256")
        != expected.release_acceptance_manifest_sha256
        or real_host_verification.get("release_id") != candidate.release_id
        or real_host_verification.get("source_git_commit") != candidate.git_commit
        or real_host_verification.get("evidence_manifest_sha256")
        != expected.real_host_manifest_sha256
    ):
        raise _validation_error("m61_evidence_binding")

    commit = resolve_clean_repository_commit(repository_path, require_no_ignored_untracked=True)
    if commit != candidate.git_commit:
        raise _validation_error("source_commit_binding")
    validate_runtime_repository_binding(repository_path, commit)

    summary = PilotSummary(
        created_at=created_at,
        release_identity=ReleaseIdentity(
            release_id=candidate.release_id,
            source_git_commit=candidate.git_commit,
            controller_version=candidate.controller_version,
            probe_version=candidate.probe_version,
            remote_executor_version=candidate.remote_executor_version,
            compiler_version=candidate.compiler_version,
            registry_version=candidate.registry_version,
            schema_version=candidate.schema_version,
            cli_contract_version=candidate.cli_contract_version,
        ),
        evidence_bindings=EvidenceBindings(
            candidate_manifest_sha256=candidate_verification.evidence_manifest_sha256,
            release_acceptance_manifest_sha256=expected.release_acceptance_manifest_sha256,
            real_host_manifest_sha256=expected.real_host_manifest_sha256,
            normalized_sanitized_record_sha256=_sha256(normalized_record_payload),
        ),
        sanitized_record=normalized_record,
        criteria=_derive_criteria(normalized_record),
        limitations=list(_LIMITATIONS),
    )
    summary_payload = _render_json(summary.model_dump(mode="json"))
    report_payload = _render_review_draft(summary)
    _assert_sanitized(
        {PILOT_SUMMARY_NAME: summary_payload, PILOT_REPORT_NAME: report_payload},
        private_paths=(
            repository_path,
            candidate_root,
            acceptance_root,
            real_host_root,
            record_path,
            output_path,
        ),
    )
    payloads = {PILOT_SUMMARY_NAME: summary_payload, PILOT_REPORT_NAME: report_payload}
    payloads["SHA256SUMS"] = checksum_payloads(payloads)

    if (
        verify_release_evidence(candidate_root) != candidate_verification
        or verify_release_acceptance_evidence(acceptance_root) != acceptance_verification
        or verify_real_host_acceptance_evidence(real_host_root) != real_host_verification
    ):
        raise _validation_error("m61_evidence_changed")
    if (
        resolve_clean_repository_commit(repository_path, require_no_ignored_untracked=True)
        != commit
    ):
        raise _validation_error("repository_changed")
    EvidenceBundleStore(output_path).create(payloads)
    return verify_pilot_evidence(output_path)


def verify_pilot_evidence(directory: str | Path) -> PilotEvidenceVerification:
    """Verify the fixed bundle offline without Git, subprocess, network, or project access."""

    payloads = _read_evidence_directory(Path(directory).absolute())
    summary = _load_model(payloads[PILOT_SUMMARY_NAME], PilotSummary, role="pilot_summary")
    if payloads[PILOT_SUMMARY_NAME] != _render_json(summary.model_dump(mode="json")):
        raise _validation_error("noncanonical_summary")
    if payloads[PILOT_REPORT_NAME] != _render_review_draft(summary):
        raise _validation_error("review_draft_projection")
    try:
        expected = parse_checksum_manifest(payloads["SHA256SUMS"], expected_names=_CORE_NAMES)
    except ValueError as exc:
        raise _validation_error("checksum_manifest") from exc
    observed = {name: _sha256(payloads[name]) for name in sorted(_CORE_NAMES)}
    if expected != observed:
        raise _validation_error("bundle_checksum")
    _assert_sanitized(
        {name: payloads[name] for name in _CORE_NAMES},
        private_paths=(),
    )
    return PilotEvidenceVerification(
        pilot_id=summary.sanitized_record.pilot_id,
        source_git_commit=summary.release_identity.source_git_commit,
        criteria_state=summary.criteria.criteria_state,
        evidence_manifest_sha256=_sha256(payloads["SHA256SUMS"]),
    )


def _derive_criteria(record: SanitizedPilotRecord) -> PilotCriteria:
    successful_cases = [
        item
        for item in record.cases
        if item.scenario in _SUCCESS_SCENARIOS and item.state == "succeeded"
    ]
    successful = len(successful_cases)
    success_identity_hashes_unique = (
        successful == 3
        and all(
            len({cast(str, getattr(item.hashes, role)) for item in successful_cases}) == 3
            for role in ("project_hash", "bundle_hash")
        )
        and len({cast(str, item.run_id_sha256) for item in successful_cases}) == 3
    )
    required_outcomes = {item.scenario: item.state for item in record.cases} == {
        "plain_fastq_single_end": "succeeded",
        "gzip_paired_end": "succeeded",
        "paired_end_multi_lane": "succeeded",
        "missing_mate": "blocked",
        "ambiguous_naming": "resolved",
        "synthetic_execution_failure": "failed_queryable",
    }
    completed_drills = sum(item.state == "recovered" for item in record.drills)
    success_audit = (
        all(
            item.reported_audit.all_passed()
            for item in record.cases
            if item.scenario in _SUCCESS_SCENARIOS and item.state == "succeeded"
        )
        and successful == 3
    )
    owners = all(
        item.status == "recorded_in_restricted_system" for item in record.owner_assignments
    )
    capacity = (
        record.capacity_retention.capacity_decision == "approved"
        and record.capacity_retention.retention_decision in {"approved", "hold"}
    )
    unresolved_blocking = sum(
        item.impact == "blocking" and item.status != "resolved" for item in record.friction
    )
    conditions = (
        required_outcomes,
        completed_drills >= 3,
        success_identity_hashes_unique,
        success_audit,
        owners,
        capacity,
        record.backup_restore.status == "passed",
        record.operator_documentation.result == "completed_from_documentation_only",
        record.friction_review_status != "not_recorded",
        record.entry_gate.status == "recorded_complete_in_restricted_system",
        unresolved_blocking == 0,
        record.control_deviation.status == "none",
        all(item.control_relaxed is False for item in record.drills),
        record.controls_relaxed is False,
        record.next_recommendation == "request_independent_m62_review",
    )
    return PilotCriteria(
        recorded_successful_case_count=successful,
        recorded_recovered_drill_count=completed_drills,
        evidence_missing_case_count=sum(item.state == "evidence_missing" for item in record.cases),
        unresolved_blocking_friction_count=unresolved_blocking,
        required_case_outcomes_recorded=required_outcomes,
        minimum_failure_drills_recorded=completed_drills >= 3,
        success_identity_hashes_unique=success_identity_hashes_unique,
        all_success_audit_checks_recorded_passed=success_audit,
        operational_owners_recorded=owners,
        capacity_and_retention_decisions_recorded=capacity,
        backup_restore_recorded_passed=record.backup_restore.status == "passed",
        documentation_only_operation_recorded=(
            record.operator_documentation.result == "completed_from_documentation_only"
        ),
        friction_review_recorded=record.friction_review_status != "not_recorded",
        entry_gate_recorded_complete=(
            record.entry_gate.status == "recorded_complete_in_restricted_system"
        ),
        criteria_state=(
            "READY_FOR_INDEPENDENT_REVIEW" if all(conditions) else "INCOMPLETE_OR_BLOCKED"
        ),
    )


def _normalized_record_dict(record: SanitizedPilotRecord) -> dict[str, Any]:
    value = record.model_dump(mode="json")
    value["cases"] = sorted(value["cases"], key=lambda item: item["case_id"])
    for item in value["cases"]:
        item["external_command_error_codes"] = sorted(item["external_command_error_codes"])
    value["drills"] = sorted(value["drills"], key=lambda item: item["drill_id"])
    value["owner_assignments"] = sorted(value["owner_assignments"], key=lambda item: item["role"])
    value["friction"] = sorted(value["friction"], key=lambda item: item["friction_id"])
    value["corrective_actions"] = sorted(
        value["corrective_actions"], key=lambda item: item["action_id"]
    )
    return value


def _render_review_draft(summary: PilotSummary) -> bytes:
    record = summary.sanitized_record
    criteria = summary.criteria
    lines = [
        "# Internal pilot review draft",
        "",
        "> **Record state: `OPERATOR_RECORDED_UNREVIEWED`**",
        "> **M6.2 decision: `BLOCKED`**",
        "> This draft proves only strict structure, deterministic projection, and bundle",
        "> integrity.",
        "> It does not prove pilot execution, evidence authenticity, independent runs, review,",
        "> sign-off, scientific correctness, or production authorization.",
        "",
        "## Bound identity",
        "",
        f"- Pilot ID: `{record.pilot_id}`",
        f"- Anonymous environment ID: `{record.environment_id}`",
        f"- Release candidate: `{summary.release_identity.release_id}`",
        f"- Exact source commit: `{summary.release_identity.source_git_commit}`",
        f"- Record time: `{record.recorded_at}`",
        f"- Bundle creation time: `{summary.created_at}`",
        f"- Collection policy: `{record.collection_policy_version}`",
        "",
        "## Machine-derived completeness",
        "",
        f"- Criteria state: `{criteria.criteria_state}`",
        f"- Recorded successful execution cases: `{criteria.recorded_successful_case_count}`",
        f"- Recorded recovered failure drills: `{criteria.recorded_recovered_drill_count}`",
        f"- M6.1 entry-gate record: `{record.entry_gate.status}`",
        f"- Cases with missing evidence: `{criteria.evidence_missing_case_count}`",
        f"- Unresolved blocking friction: `{criteria.unresolved_blocking_friction_count}`",
        f"- Next recommendation: `{record.next_recommendation}`",
        "",
        "Even `READY_FOR_INDEPENDENT_REVIEW` is not acceptance. The milestone decision remains",
        "`BLOCKED` until a human reviewer verifies controlled source evidence and signs off.",
        "",
        "## Required cases",
        "",
        "| Anonymous case | Scenario | Recorded state | Samples | Lanes | Audit |",
        "|---|---|---|---:|---:|---|",
    ]
    for case_record in record.cases:
        samples = (
            "not-recorded"
            if case_record.manifest_sample_count is None
            else str(case_record.manifest_sample_count)
        )
        lanes = (
            "not-recorded"
            if case_record.manifest_lane_count is None
            else str(case_record.manifest_lane_count)
        )
        audit = (
            "recorded-passed" if case_record.reported_audit.all_passed() else "not-recorded-passed"
        )
        lines.append(
            f"| `{case_record.case_id}` | `{case_record.scenario}` | `{case_record.state}` | "
            f"{samples} | {lanes} | "
            f"`{audit}` |"
        )
    lines.extend(
        [
            "",
            "## Failure drills",
            "",
            "| Anonymous drill | Type | Recorded state | Expected code | Observed code |",
            "|---|---|---|---|---|",
        ]
    )
    if record.drills:
        for drill_record in record.drills:
            lines.append(
                f"| `{drill_record.drill_id}` | `{drill_record.drill_type}` | "
                f"`{drill_record.state}` | `{drill_record.expected_code}` | "
                f"`{drill_record.observed_code}` |"
            )
    else:
        lines.append("| `none` | `none` | `unexecuted` | `NOT_OBSERVED` | `NOT_OBSERVED` |")
    lines.extend(
        [
            "",
            "## Operator friction and actions",
            "",
            "| Friction | Step | Impact | Status | Action |",
            "|---|---|---|---|---|",
        ]
    )
    if record.friction:
        for friction_record in record.friction:
            action = friction_record.action_id or "none"
            lines.append(
                f"| `{friction_record.friction_id}` | `{friction_record.step}` | "
                f"`{friction_record.impact}` | `{friction_record.status}` | `{action}` |"
            )
    else:
        empty_state = (
            "recorded-none" if record.friction_review_status == "recorded_none" else "not-recorded"
        )
        lines.append(f"| `{empty_state}` | `none` | `low` | `resolved` | `none` |")
    lines.extend(
        [
            "",
            "### Corrective actions",
            "",
            "| Action | Friction | Owner role | Priority | Status | Due | Verification |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    if record.corrective_actions:
        for action_record in record.corrective_actions:
            lines.append(
                f"| `{action_record.action_id}` | `{action_record.friction_id}` | "
                f"`{action_record.owner_role}` | `{action_record.priority}` | "
                f"`{action_record.status}` | `{action_record.due_date}` | "
                f"`{action_record.verification_method}` |"
            )
    else:
        lines.append("| `none-recorded` | `none` | `none` | `none` | `none` | `none` | `none` |")
    lines.extend(
        [
            "",
            "## Governance, capacity, and retention",
            "",
            f"- Friction review: `{record.friction_review_status}`",
            f"- Operator documentation result: `{record.operator_documentation.result}`",
            f"- Backup restore: `{record.backup_restore.status}`",
            f"- Control deviation: `{record.control_deviation.status}`",
            f"- Capacity decision: `{record.capacity_retention.capacity_decision}`",
            f"- Retention decision: `{record.capacity_retention.retention_decision}`",
            f"- Deploy usage: `{record.capacity_retention.deploy_usage_bucket}`",
            f"- Work usage: `{record.capacity_retention.work_usage_bucket}`",
            f"- Output usage: `{record.capacity_retention.output_usage_bucket}`",
            f"- Cache usage: `{record.capacity_retention.cache_usage_bucket}`",
            "",
            "| Operational role | Restricted assignment state |",
            "|---|---|",
        ]
    )
    for assignment in record.owner_assignments:
        lines.append(f"| `{assignment.role}` | `{assignment.status}` |")
    lines.extend(
        [
            "",
            "## Evidence bindings",
            "",
            f"- Candidate manifest: `{summary.evidence_bindings.candidate_manifest_sha256}`",
            "- Release-acceptance manifest: "
            f"`{summary.evidence_bindings.release_acceptance_manifest_sha256}`",
            f"- Real-host manifest: `{summary.evidence_bindings.real_host_manifest_sha256}`",
            "- Normalized sanitized record: "
            f"`{summary.evidence_bindings.normalized_sanitized_record_sha256}`",
        ]
    )
    lines.extend(
        [
            "",
            "## Fixed limitations",
            "",
            *(f"- `{item}`" for item in summary.limitations),
            "",
        ]
    )
    return "\n".join(lines).encode("ascii")


def _load_model(payload: bytes, model: type[BaseModel], *, role: str) -> Any:
    value = _decode_json(payload, role=role)
    try:
        return model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise _validation_error(role) from exc


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


def _render_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _assert_sanitized(payloads: dict[str, bytes], *, private_paths: tuple[Path, ...]) -> None:
    forbidden = (
        b"/Users/",
        b"/home/",
        b"file://",
        b"\\\\",
        b"PRIVATE KEY",
        b"Authorization:",
        b"Bearer ",
        b"approval.key",
        b".fastq",
        b".fq",
        b"@A0",
    )
    fragments = tuple(
        os.fsencode(path.absolute())
        for path in private_paths
        if len(os.fspath(path.absolute())) >= 4
    )
    if any(marker in payload for payload in payloads.values() for marker in forbidden) or any(
        fragment in payload for payload in payloads.values() for fragment in fragments
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
        raise OSError("invalid pilot evidence directory")
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
        if frozenset(os.listdir(descriptor)) != PILOT_EVIDENCE_NAMES:
            raise OSError("unexpected pilot evidence file set")
        payloads: dict[str, bytes] = {}
        total = 0
        for name in sorted(PILOT_EVIDENCE_NAMES):
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
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not 0 < before.st_size <= _MAX_EVIDENCE_BYTES
                ):
                    raise OSError("unsafe pilot evidence file")
                payload = bytearray()
                while chunk := os.read(
                    file_descriptor,
                    min(1024 * 1024, _MAX_EVIDENCE_BYTES + 1 - len(payload)),
                ):
                    payload.extend(chunk)
                    if len(payload) > _MAX_EVIDENCE_BYTES:
                        raise OSError("pilot evidence file exceeds its bound")
                after = os.fstat(file_descriptor)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if len(payload) != before.st_size or any(
                    getattr(before, field) != getattr(after, field) for field in stable_fields
                ):
                    raise OSError("pilot evidence file changed while reading")
                payloads[name] = bytes(payload)
                total += len(payload)
            finally:
                os.close(file_descriptor)
        if total > _MAX_BUNDLE_BYTES or frozenset(os.listdir(descriptor)) != PILOT_EVIDENCE_NAMES:
            raise OSError("pilot evidence directory changed while reading")
        return payloads
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "Internal pilot evidence is missing, unsafe, or incomplete.",
            remediation=["Use the exact create-only sanitized pilot evidence bundle."],
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validation_error(reason: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "Internal pilot evidence did not satisfy the reviewed privacy-safe format.",
        context={"reason": reason},
        remediation=[
            "Correct the site-controlled record without weakening a control, then create a new "
            "bundle."
        ],
    )


__all__ = [
    "PILOT_EVIDENCE_NAMES",
    "PILOT_REPORT_NAME",
    "PILOT_SUMMARY_NAME",
    "PilotEvidenceVerification",
    "SanitizedPilotRecord",
    "create_pilot_evidence",
    "verify_pilot_evidence",
]
