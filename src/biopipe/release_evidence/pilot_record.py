"""Safe authoring helpers for the strict sanitized internal-pilot record.

The initializer creates only an explicitly unexecuted, blocked record.  The
validator checks format and cross-field consistency offline; neither operation
authenticates source evidence, reads a project, or performs a pilot action.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from biopipe.errors import BioPipeError
from biopipe.release_evidence.checksums import read_bounded_regular
from biopipe.release_evidence.filesystem import FileIdentity
from biopipe.release_evidence.pilot import (
    _MAX_INPUT_BYTES,
    _OWNER_ROLES,
    _REQUIRED_CASE_SCENARIOS,
    _UNEXECUTED_DRILL_TEMPLATES,
    SanitizedPilotRecord,
    _assert_sanitized,
    _lexical_absolute,
    _load_model,
    _normalized_record_dict,
    _path_is_inside_protected_root,
    _render_json,
    _required_directory_identity,
    _sha256,
    _validation_error,
)
from biopipe.release_evidence.store import EvidenceBundleStore


class PilotRecordValidation(BaseModel):
    """Privacy-safe result of strict record-format validation only."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    pilot_id: str = Field(pattern=r"^pilot-[0-9]{8}-[0-9]{3}$")
    exact_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_sanitized_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_json: bool
    record_state: Literal["STRICT_FORMAT_VALIDATED_ONLY"] = "STRICT_FORMAT_VALIDATED_ONLY"
    source_evidence_authentication_status: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    independent_review_status: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    milestone_decision: Literal["BLOCKED"] = "BLOCKED"
    production_authorization: Literal[False] = False
    network_accessed: Literal[False] = False
    project_tree_read: Literal[False] = False
    private_state_read: Literal[False] = False
    raw_content_exported: Literal[False] = False


def _unobserved_gate() -> dict[str, str]:
    return {"status": "not_observed", "code": "NOT_OBSERVED"}


def _unperformed_audit() -> dict[str, str]:
    return {
        "parse_status": "not_performed",
        "order_status": "not_performed",
        "authorization_binding_status": "not_performed",
        "terminal_binding_status": "not_performed",
    }


def _empty_case_hashes() -> dict[str, None]:
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


def _unexecuted_case(case_id: str, scenario: str) -> dict[str, Any]:
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
        "reported_audit": _unperformed_audit(),
        "hashes": _empty_case_hashes(),
        "run_id_sha256": None,
        "attribution_record_sha256": None,
        "controlled_evidence_sha256": None,
    }


def build_unexecuted_pilot_record(
    *,
    pilot_id: str,
    environment_id: str,
    recorded_at: str,
    release_id: str,
    source_git_commit: str,
    candidate_manifest_sha256: str,
    release_acceptance_manifest_sha256: str,
    real_host_manifest_sha256: str,
) -> SanitizedPilotRecord:
    """Build one strict record whose every observation remains unexecuted."""

    value: dict[str, Any] = {
        "format_version": "1.0",
        "collection_policy_version": "1.0",
        "pilot_id": pilot_id,
        "environment_id": environment_id,
        "recorded_at": recorded_at,
        "data_boundary": "non_sensitive_only",
        "expected_evidence": {
            "release_id": release_id,
            "source_git_commit": source_git_commit,
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "release_acceptance_manifest_sha256": release_acceptance_manifest_sha256,
            "real_host_manifest_sha256": real_host_manifest_sha256,
        },
        "entry_gate": {"status": "not_recorded", "restricted_record_sha256": None},
        "cases": [
            _unexecuted_case(f"case-{index:03d}", scenario)
            for index, scenario in enumerate(_REQUIRED_CASE_SCENARIOS, start=1)
        ],
        "drills": [
            {
                "drill_id": f"drill-{index:03d}",
                "drill_type": drill_type,
                "state": "unexecuted",
                "expected_code": expected_code,
                "observed_code": "NOT_OBSERVED",
                "observed_at": None,
                "control_relaxed": False,
                "controlled_evidence_sha256": None,
            }
            for index, (drill_type, expected_code) in enumerate(
                _UNEXECUTED_DRILL_TEMPLATES, start=1
            )
        ],
        "owner_assignments": [
            {"role": role, "status": "pending", "restricted_record_sha256": None}
            for role in _OWNER_ROLES
        ],
        "capacity_retention": {
            "deploy_usage_bucket": "not_observed",
            "work_usage_bucket": "not_observed",
            "output_usage_bucket": "not_observed",
            "cache_usage_bucket": "not_observed",
            "capacity_decision": "pending",
            "retention_decision": "pending",
            "restricted_record_sha256": None,
        },
        "backup_restore": {"status": "not_run", "restricted_record_sha256": None},
        "operator_documentation": {
            "result": "not_observed",
            "restricted_record_sha256": None,
        },
        "friction_review_status": "not_recorded",
        "friction": [],
        "corrective_actions": [],
        "control_deviation": {"status": "none", "restricted_record_sha256": None},
        "controls_relaxed": False,
        "next_recommendation": "remain_blocked",
    }
    return cast(
        SanitizedPilotRecord,
        _load_model(
            _render_json(value),
            SanitizedPilotRecord,
            role="pilot_record_template_parameters",
        ),
    )


def _external_record_path(
    *, repository: str | Path, record_path: str | Path, path_role: str
) -> tuple[Path, Path, FileIdentity]:
    repository_path = _lexical_absolute(repository, role="repository_path")
    external_path = _lexical_absolute(record_path, role=path_role)
    repository_identity = _required_directory_identity(repository_path)
    if _path_is_inside_protected_root(
        external_path,
        repository_path,
        root_identity=repository_identity,
    ):
        raise _validation_error("private_path_inside_repository")
    return repository_path, external_path, repository_identity


def _validation_result(*, record: SanitizedPilotRecord, payload: bytes) -> PilotRecordValidation:
    normalized_payload = _render_json(_normalized_record_dict(record))
    return PilotRecordValidation(
        pilot_id=record.pilot_id,
        exact_record_sha256=_sha256(payload),
        normalized_sanitized_record_sha256=_sha256(normalized_payload),
        canonical_json=payload == normalized_payload,
    )


def validate_sanitized_pilot_record(
    *, repository: str | Path, record_file: str | Path
) -> PilotRecordValidation:
    """Validate one external sanitized record without authenticating its facts."""

    try:
        return _validate_sanitized_pilot_record(
            repository=repository,
            record_file=record_file,
        )
    except BioPipeError as exc:
        exc.__cause__ = None
        exc.__context__ = None
        exc.__suppress_context__ = True
        raise


def _validate_sanitized_pilot_record(
    *, repository: str | Path, record_file: str | Path
) -> PilotRecordValidation:
    _repository_path, record_path, repository_identity = _external_record_path(
        repository=repository,
        record_path=record_file,
        path_role="sanitized_record_path",
    )
    payload = read_bounded_regular(
        record_path,
        role="sanitized_pilot_record",
        limit_bytes=_MAX_INPUT_BYTES,
        require_private_file=True,
        forbidden_directory_identities=frozenset({repository_identity}),
    )
    record = cast(
        SanitizedPilotRecord,
        _load_model(payload, SanitizedPilotRecord, role="sanitized_pilot_record"),
    )
    return _validation_result(record=record, payload=payload)


def create_unexecuted_pilot_record(
    *,
    repository: str | Path,
    output_file: str | Path,
    pilot_id: str,
    environment_id: str,
    recorded_at: str,
    release_id: str,
    source_git_commit: str,
    candidate_manifest_sha256: str,
    release_acceptance_manifest_sha256: str,
    real_host_manifest_sha256: str,
) -> PilotRecordValidation:
    """Create one private, canonical, unexecuted record without replacement."""

    try:
        return _create_unexecuted_pilot_record(
            repository=repository,
            output_file=output_file,
            pilot_id=pilot_id,
            environment_id=environment_id,
            recorded_at=recorded_at,
            release_id=release_id,
            source_git_commit=source_git_commit,
            candidate_manifest_sha256=candidate_manifest_sha256,
            release_acceptance_manifest_sha256=release_acceptance_manifest_sha256,
            real_host_manifest_sha256=real_host_manifest_sha256,
        )
    except BioPipeError as exc:
        exc.__cause__ = None
        exc.__context__ = None
        exc.__suppress_context__ = True
        raise


def _create_unexecuted_pilot_record(
    *,
    repository: str | Path,
    output_file: str | Path,
    pilot_id: str,
    environment_id: str,
    recorded_at: str,
    release_id: str,
    source_git_commit: str,
    candidate_manifest_sha256: str,
    release_acceptance_manifest_sha256: str,
    real_host_manifest_sha256: str,
) -> PilotRecordValidation:
    repository_path, output_path, repository_identity = _external_record_path(
        repository=repository,
        record_path=output_file,
        path_role="sanitized_record_output_path",
    )
    record = build_unexecuted_pilot_record(
        pilot_id=pilot_id,
        environment_id=environment_id,
        recorded_at=recorded_at,
        release_id=release_id,
        source_git_commit=source_git_commit,
        candidate_manifest_sha256=candidate_manifest_sha256,
        release_acceptance_manifest_sha256=release_acceptance_manifest_sha256,
        real_host_manifest_sha256=real_host_manifest_sha256,
    )
    payload = _render_json(_normalized_record_dict(record))
    _assert_sanitized(
        {output_path.name: payload},
        private_paths=(repository_path, output_path),
    )
    EvidenceBundleStore.create_file(
        output_path,
        payload,
        forbidden_directory_identities=frozenset({repository_identity}),
    )
    return _validation_result(record=record, payload=payload)


__all__ = [
    "PilotRecordValidation",
    "build_unexecuted_pilot_record",
    "create_unexecuted_pilot_record",
    "validate_sanitized_pilot_record",
]
