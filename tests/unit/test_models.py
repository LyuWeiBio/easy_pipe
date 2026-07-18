"""Contract tests for the public M0 Pydantic models."""

from __future__ import annotations

from copy import deepcopy
import json

import pytest
from pydantic import BaseModel, ValidationError

from biopipe.models import (
    AuditEvent,
    DatasetManifest,
    ExecutionPlan,
    ManifestOverrides,
    PipelineSpec,
    ProbeRequest,
    ProbeResponse,
    SoftwareLock,
    SourceProfile,
)


MODEL_TYPES = (
    SourceProfile,
    ProbeRequest,
    ProbeResponse,
    DatasetManifest,
    ManifestOverrides,
    PipelineSpec,
    SoftwareLock,
    ExecutionPlan,
    AuditEvent,
)

VERSION_FIELDS = {
    SourceProfile: "schema_version",
    ProbeRequest: "protocol_version",
    ProbeResponse: "protocol_version",
    DatasetManifest: "manifest_version",
    ManifestOverrides: "override_version",
    PipelineSpec: "spec_version",
    SoftwareLock: "lock_version",
    ExecutionPlan: "plan_version",
    AuditEvent: "schema_version",
}

VALID_MODEL_PAYLOADS = (
    (
        SourceProfile,
        {
            "source_id": "synthetic-source",
            "ssh_alias": "synthetic-host",
            "allowed_roots": ["/srv/synthetic-raw"],
        },
    ),
    (
        ProbeRequest,
        {
            "request_id": "health-001",
            "operation": "health",
        },
    ),
    (
        ProbeResponse,
        {
            "request_id": "health-001",
            "success": True,
            "return_code": 0,
            "result": {"status": "healthy"},
        },
    ),
    (
        DatasetManifest,
        {
            "source": {
                "source_id": "synthetic-source",
                "root": "/srv/synthetic-raw/run-001",
                "scanned_at": "2026-01-01T00:00:00Z",
                "scan_policy": "format_summary",
            },
            "classification": {
                "dataset_type": "generic_fastq",
                "layout": "single_end",
                "confidence": 0.9,
            },
            "samples": [
                {
                    "sample_id": "sample-001",
                    "lanes": [
                        {
                            "lane": "L001",
                            "read1": "/srv/synthetic-raw/run-001/sample_R1.fastq.gz",
                        }
                    ],
                }
            ],
        },
    ),
    (
        ManifestOverrides,
        {
            "rename_samples": {"sample-001": "control-001"},
            "reason": "Synthetic naming correction.",
            "approved_by": "pytest",
        },
    ),
    (
        PipelineSpec,
        {
            "project": {"name": "synthetic-fastq-qc"},
            "input": {
                "manifest": "dataset.manifest.resolved.json",
                "layout": "single_end",
            },
            "paths": {
                "work_dir": "/srv/work/synthetic-fastq-qc",
                "output_dir": "/srv/results/synthetic-fastq-qc",
                "container_cache": "/srv/cache/apptainer",
            },
        },
    ),
    (
        SoftwareLock,
        {
            "components": {
                "fastqc": {
                    "version": "0.12.1",
                    "image": "registry.example/fastqc:0.12.1",
                    "digest": f"sha256:{'a' * 64}",
                    "license": "GPL-3.0-or-later",
                }
            },
            "resolved_at": "2026-01-01T00:00:00Z",
            "resolver_version": "m0-static-fixture",
        },
    ),
    (
        ExecutionPlan,
        {
            "source_host": "synthetic-source",
            "execution_host": "synthetic-executor",
            "paths": {
                "source_root": "/srv/synthetic-raw/run-001",
                "execution_root": "/srv/synthetic-raw/run-001",
                "work_dir": "/srv/work/synthetic-fastq-qc",
                "output_dir": "/srv/results/synthetic-fastq-qc",
                "container_cache": "/srv/cache/apptainer",
            },
        },
    ),
    (
        AuditEvent,
        {
            "event_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "TEST_COMPLETED",
            "project_id": "synthetic-project",
            "actor": "pytest",
            "status": "success",
            "summary": "Synthetic M0 audit event.",
        },
    ),
)
VALID_MODEL_PAYLOAD_BY_TYPE = dict(VALID_MODEL_PAYLOADS)


@pytest.mark.parametrize("model_type", MODEL_TYPES)
def test_public_models_are_strict_pydantic_models(
    model_type: type[BaseModel],
) -> None:
    assert issubclass(model_type, BaseModel)
    assert model_type.model_config.get("extra") == "forbid"


@pytest.mark.parametrize("model_type", MODEL_TYPES)
def test_public_models_publish_json_schema(model_type: type[BaseModel]) -> None:
    schema = model_type.model_json_schema()

    assert schema["type"] == "object"
    assert VERSION_FIELDS[model_type] in schema["properties"]
    assert schema["additionalProperties"] is False
    nested_models = [
        definition
        for definition in schema.get("$defs", {}).values()
        if definition.get("type") == "object" and "properties" in definition
    ]
    assert all(definition.get("additionalProperties") is False for definition in nested_models)
    # A generated schema must itself be JSON serializable for CLI/file export.
    json.dumps(schema)


@pytest.mark.parametrize("model_type", MODEL_TYPES)
def test_public_model_versions_default_to_one(model_type: type[BaseModel]) -> None:
    version_field = VERSION_FIELDS[model_type]

    assert model_type.model_fields[version_field].default == "1.0"


@pytest.mark.parametrize(
    ("model_type", "payload"),
    VALID_MODEL_PAYLOADS,
    ids=[model_type.__name__ for model_type, _ in VALID_MODEL_PAYLOADS],
)
def test_public_models_validate_and_round_trip_json(
    model_type: type[BaseModel],
    payload: dict[str, object],
) -> None:
    model = model_type.model_validate(payload)

    assert model_type.model_validate_json(model.model_dump_json()) == model

    with pytest.raises(ValidationError) as exc_info:
        model_type.model_validate({**payload, "unexpected": True})

    assert any(error["type"] == "extra_forbidden" for error in exc_info.value.errors())


def test_source_profile_has_deny_by_default_security_settings() -> None:
    profile = SourceProfile.model_validate(
        {
            "schema_version": "1.0",
            "source_id": "synthetic-source",
            "ssh_alias": "synthetic-host",
            "allowed_roots": ["/srv/synthetic-raw"],
            "probe": {
                "remote_path": "~/.local/bin/bioprobe.pyz",
                "max_runtime_seconds": 300,
                "max_depth": 6,
                "max_entries": 100_000,
                "follow_symlinks": False,
            },
            "privacy": {
                "filenames_sensitive": True,
                "allow_external_llm": False,
            },
        }
    )

    assert profile.probe.follow_symlinks is False
    assert profile.privacy.allow_external_llm is False


def test_source_profile_rejects_unknown_nested_fields() -> None:
    payload = {
        "schema_version": "1.0",
        "source_id": "synthetic-source",
        "ssh_alias": "synthetic-host",
        "allowed_roots": ["/srv/synthetic-raw"],
        "probe": {"follow_symlinks": False},
        "privacy": {
            "filenames_sensitive": True,
            "allow_external_llm": False,
            "password": "must-not-be-accepted",
        },
    }

    with pytest.raises(ValidationError) as exc_info:
        SourceProfile.model_validate(payload)

    assert any(error["type"] == "extra_forbidden" for error in exc_info.value.errors())


def test_probe_policy_defaults_do_not_export_raw_fastq_content() -> None:
    request = ProbeRequest.model_validate(VALID_MODEL_PAYLOAD_BY_TYPE[ProbeRequest])

    assert request.policy.follow_symlinks is False
    assert request.policy.return_sequences is False
    assert request.policy.return_qualities is False
    assert request.policy.return_read_names is False


@pytest.mark.parametrize(
    "raw_export_flag",
    ["return_sequences", "return_qualities", "return_read_names"],
)
def test_probe_policy_rejects_raw_fastq_export_flags(raw_export_flag: str) -> None:
    with pytest.raises(ValidationError):
        ProbeRequest.model_validate(
            {
                "request_id": "scan-001",
                "operation": "summarize_fastq",
                "root": "/srv/synthetic-raw",
                "policy": {raw_export_flag: True},
            }
        )


def test_execution_contracts_default_to_no_real_data_run() -> None:
    specification = PipelineSpec.model_validate(VALID_MODEL_PAYLOAD_BY_TYPE[PipelineSpec])
    execution_plan = ExecutionPlan.model_validate(
        VALID_MODEL_PAYLOAD_BY_TYPE[ExecutionPlan]
    )

    assert specification.policy.network_access_during_tasks is False
    assert specification.policy.run_real_data is False
    assert specification.policy.require_real_data_approval is True
    assert specification.policy.overwrite_existing_outputs is False
    assert execution_plan.approval.real_data_execution_required is True
    assert execution_plan.approval.approved is False


def test_paired_manifest_rejects_lane_without_read2() -> None:
    payload = deepcopy(VALID_MODEL_PAYLOAD_BY_TYPE[DatasetManifest])
    payload["classification"]["layout"] = "paired_end"

    with pytest.raises(ValidationError):
        DatasetManifest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("image", "registry.example/fastqc:latest"),
        ("digest", "sha256:not-a-pinned-digest"),
    ],
)
def test_software_lock_rejects_unpinned_components(
    field: str,
    invalid_value: str,
) -> None:
    payload = deepcopy(VALID_MODEL_PAYLOAD_BY_TYPE[SoftwareLock])
    payload["components"]["fastqc"][field] = invalid_value

    with pytest.raises(ValidationError):
        SoftwareLock.model_validate(payload)


def test_execution_approval_requires_attribution_and_artifact_hashes() -> None:
    payload = deepcopy(VALID_MODEL_PAYLOAD_BY_TYPE[ExecutionPlan])
    payload["approval"] = {
        "real_data_execution_required": True,
        "approved": True,
    }

    with pytest.raises(ValidationError):
        ExecutionPlan.model_validate(payload)

    payload["approval"] = {
        "real_data_execution_required": True,
        "approved": True,
        "approved_by": "pytest",
        "approved_at": "2026-01-01T00:00:00Z",
        "artifact_hashes": {"pipeline.spec.yaml": "b" * 64},
    }
    approved_plan = ExecutionPlan.model_validate(payload)

    assert approved_plan.approval.approved is True
