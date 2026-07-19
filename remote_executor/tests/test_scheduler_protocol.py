"""Offline tests for the dormant scheduler protocol-v2 contract."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import hmac
import json
import os
import socket
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from bioexec.errors import AgentFailure
from bioexec.protocol import parse_request as parse_v1_request
from bioexec.scheduler_protocol import (
    PROTOCOL_VERSION,
    SchedulerProtocolError,
    SchedulerRequest,
    SlurmRunEvidence,
    canonical_hmac_envelope_bytes,
    decode_json_line,
    parse_request,
    parse_slurm_run_evidence,
)

_PROFILE_HASH = "a" * 64
_POLICY_HASH = "b" * 64
_SIGNATURE = "d" * 64
_MARKER = "e" * 64
_SCRIPT_HASH = "f" * 64

_CORE_HASHES = {
    "dataset_manifest": "1" * 64,
    "pipeline_spec": "2" * 64,
    "execution_plan": "3" * 64,
    "software_lock": "4" * 64,
    "execution_profile": _PROFILE_HASH,
}


def _canonical_hash(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


_DEPLOY_CONTENT = b"synthetic\n"
_DEPLOY_FILE_SHA256 = hashlib.sha256(_DEPLOY_CONTENT).hexdigest()
_BUNDLE_HASH = _canonical_hash(
    [
        {
            "path": "main.nf",
            "sha256": _DEPLOY_FILE_SHA256,
            "size": len(_DEPLOY_CONTENT),
        }
    ]
)
_PROJECT_HASH = _canonical_hash(
    {
        "dataset_manifest": _CORE_HASHES["dataset_manifest"],
        "execution_plan": _CORE_HASHES["execution_plan"],
        "pipeline_spec": _CORE_HASHES["pipeline_spec"],
        "software_lock": _CORE_HASHES["software_lock"],
    }
)
_COMPATIBILITY_HASH = _canonical_hash(
    {
        "bundle_hash": _BUNDLE_HASH,
        "execution_profile": _PROFILE_HASH,
        "project_hash": _PROJECT_HASH,
    }
)


def _bindings() -> dict[str, object]:
    return {
        "profile_version": "2.0",
        "profile_id": "slurm-profile-1",
        "profile_hash": _PROFILE_HASH,
        "scheduler_policy_hash": _POLICY_HASH,
    }


def _approval() -> dict[str, object]:
    return {
        "approved": True,
        "authorization_id": "auth-1",
        "actor": "operator-一",
        "approved_at": "2026-07-19T12:30:00Z",
        "artifact_hashes": {
            **_CORE_HASHES,
            "validation_report": "5" * 64,
            "test_report": "6" * 64,
            "preflight_report": "7" * 64,
        },
        "bundle_hash": _BUNDLE_HASH,
        "compatibility_hash": _COMPATIBILITY_HASH,
        "key_id": "controller-key-1",
        "signature": _SIGNATURE,
    }


def _preflight_payload() -> dict[str, object]:
    return {
        **_bindings(),
        "preflight_id": "preflight-1",
        "project_hash": _PROJECT_HASH,
        "artifact_hashes": dict(_CORE_HASHES),
        "source_host": "host-1",
        "execution_host": "host-1",
        "host_relation": "same",
        "source_paths": ["/srv/raw/sample_R1.fastq.gz"],
        "execution_paths": ["/srv/raw/sample_R1.fastq.gz"],
        "path_mapping": [],
        "deploy_dir": "/srv/biopipe/deploy/run-1",
        "work_dir": "/srv/biopipe/work/run-1",
        "output_dir": "/srv/biopipe/results/run-1",
        "cache_dir": "/srv/biopipe/cache/run-1",
        "container_engine": "apptainer",
        "containers": [
            {
                "name": "fastqc",
                "image": "quay.io/biocontainers/fastqc:0.12.1--0",
                "digest": f"sha256:{'8' * 64}",
                "local_path": "/srv/biopipe/cache/fastqc.sif",
                "file_sha256": "9" * 64,
            }
        ],
        "minimum_free_bytes": 1024**3,
        "network_disabled": True,
        "resume_run_id": None,
    }


def _shared_preflight_payload() -> dict[str, object]:
    payload = _preflight_payload()
    payload.update(
        {
            "source_host": "source-host",
            "execution_host": "compute-host",
            "host_relation": "shared",
            "source_paths": [
                "/source/project/sample-a.fastq.gz",
                "/source/other/sample-b.fastq.gz",
            ],
            "execution_paths": [
                "/cluster/project/sample-a.fastq.gz",
                "/cluster/other/sample-b.fastq.gz",
            ],
            "path_mapping": [
                {
                    "source_prefix": "/source",
                    "execution_prefix": "/cluster",
                },
                {
                    "source_prefix": "/source/project",
                    "execution_prefix": "/cluster/project",
                },
            ],
        }
    )
    return payload


def _deploy_payload() -> dict[str, object]:
    return {
        **_bindings(),
        "deployment_id": "deployment-1",
        "preflight_id": "preflight-1",
        "project_hash": _PROJECT_HASH,
        "bundle_hash": _BUNDLE_HASH,
        "deployment_dir": "/srv/biopipe/deploy/run-1",
        "files": [
            {
                "path": "main.nf",
                "size": len(_DEPLOY_CONTENT),
                "sha256": _DEPLOY_FILE_SHA256,
                "content_base64": base64.b64encode(_DEPLOY_CONTENT).decode("ascii"),
            }
        ],
    }


def _submit_payload() -> dict[str, object]:
    return {
        **_bindings(),
        "run_id": "run-1",
        "preflight_id": "preflight-1",
        "preflight_token": "token-1",
        "deployment_id": "deployment-1",
        "project_hash": _PROJECT_HASH,
        "bundle_hash": _BUNDLE_HASH,
        "approval": _approval(),
    }


def _status_payload() -> dict[str, object]:
    return {
        **_bindings(),
        "run_id": "run-1",
        "project_hash": _PROJECT_HASH,
        "bundle_hash": _BUNDLE_HASH,
    }


def _resume_payload() -> dict[str, object]:
    return {**_submit_payload(), "run_id": "run-2", "resume_run_id": "run-1"}


def _payload(operation: str) -> dict[str, object]:
    builders = {
        "health": dict,
        "preflight": _preflight_payload,
        "deploy": _deploy_payload,
        "submit": _submit_payload,
        "status": _status_payload,
        "resume": _resume_payload,
    }
    return builders[operation]()


def _envelope(
    operation: str,
    *,
    payload: dict[str, object] | None = None,
    protocol_version: object = "2.0",
    request_id: object = "request-1",
) -> dict[str, object]:
    return {
        "protocol_version": protocol_version,
        "request_id": request_id,
        "operation": operation,
        "payload": _payload(operation) if payload is None else payload,
    }


def _evidence(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "job_id": "12345",
        "submission_marker": _MARKER,
        "submitted_at": "2026-07-19T12:34:56",
        "batch_script_sha256": _SCRIPT_HASH,
        "scheduler_policy_hash": _POLICY_HASH,
        "raw_state": "RUNNING",
        "mapped_state": "active",
        "reason_code": "SLURM_RUNNING",
        "exit_code": None,
        "signal": None,
        "source": "squeue",
    }
    value.update(updates)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@pytest.mark.parametrize(
    "operation",
    ["health", "preflight", "deploy", "submit", "status", "resume"],
)
def test_each_exact_v2_operation_parses_to_an_immutable_request(operation: str) -> None:
    request = parse_request(_envelope(operation))

    assert isinstance(request, SchedulerRequest)
    assert request.protocol_version == "2.0"
    assert request.request_id == "request-1"
    assert request.operation == operation
    assert _thaw(request.payload) == _payload(operation)
    with pytest.raises(TypeError):
        request.payload["injected"] = True  # type: ignore[index]
    if operation in {"submit", "resume"}:
        with pytest.raises(TypeError):
            request.payload["approval"]["actor"] = "attacker"  # type: ignore[index]


def test_protocol_version_is_a_literal_and_v1_v2_cross_reject() -> None:
    assert PROTOCOL_VERSION == "2.0"

    with pytest.raises(AgentFailure):
        parse_v1_request(_envelope("health"))
    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope("health", protocol_version="1.0"))


@pytest.mark.parametrize("operation", ["cancel", "abandon", "slurm", "exec", "shell"])
def test_v2_rejects_every_unreviewed_operation(operation: str) -> None:
    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope(operation, payload={}))


@pytest.mark.parametrize(
    "mutation",
    [
        {"extra": True},
        {"protocol_version": None},
        {"request_id": None},
        {"operation": None},
        {"payload": None},
    ],
)
def test_v2_envelope_requires_every_exact_field(mutation: dict[str, object]) -> None:
    envelope = _envelope("health")
    if "extra" in mutation:
        envelope.update(mutation)
    else:
        del envelope[next(iter(mutation))]

    with pytest.raises(SchedulerProtocolError):
        parse_request(envelope)


@pytest.mark.parametrize(
    ("protocol_version", "request_id"),
    [
        ("1.0", "request-1"),
        (2.0, "request-1"),
        ("2.0\n", "request-1"),
        ("2.0", "-request"),
        ("2.0", "request 1"),
        ("2.0", "request-1\n"),
    ],
)
def test_v2_rejects_noncanonical_versions_and_request_ids(
    protocol_version: object,
    request_id: object,
) -> None:
    with pytest.raises(SchedulerProtocolError):
        parse_request(
            _envelope(
                "health",
                protocol_version=protocol_version,
                request_id=request_id,
            )
        )


@pytest.mark.parametrize(
    "operation",
    ["preflight", "deploy", "submit", "status", "resume"],
)
def test_non_health_payloads_require_every_exact_key(operation: str) -> None:
    original = _payload(operation)
    for field in original:
        missing = copy.deepcopy(original)
        del missing[field]
        with pytest.raises(SchedulerProtocolError, match="exact contract"):
            parse_request(_envelope(operation, payload=missing))

    extra = copy.deepcopy(original)
    extra["scheduler"] = {"extra_flags": ["--wrap=id"]}
    with pytest.raises(SchedulerProtocolError, match="exact contract"):
        parse_request(_envelope(operation, payload=extra))


@pytest.mark.parametrize("operation", ["submit", "status", "resume"])
@pytest.mark.parametrize(
    "forbidden",
    [
        "scheduler",
        "scheduler_policy",
        "job_id",
        "submission_marker",
        "submitted_at",
        "batch_script",
        "batch_script_sha256",
        "script_path",
        "extra_flags",
        "argv",
        "environment",
        "cancel",
    ],
)
def test_callers_cannot_supply_scheduler_mutation_or_evidence_fields(
    operation: str,
    forbidden: str,
) -> None:
    payload = _payload(operation)
    payload[forbidden] = "attacker-controlled"

    with pytest.raises(SchedulerProtocolError, match="exact contract"):
        parse_request(_envelope(operation, payload=payload))


@pytest.mark.parametrize("operation", ["preflight", "deploy", "submit", "status", "resume"])
@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("profile_version", "1.0"),
        ("profile_version", 2.0),
        ("profile_id", "-profile"),
        ("profile_hash", "A" * 64),
        ("profile_hash", "0" * 64),
        ("scheduler_policy_hash", "b" * 63),
        ("scheduler_policy_hash", "0" * 64),
    ],
)
def test_every_non_health_operation_has_strict_profile_scheduler_bindings(
    operation: str,
    field: str,
    invalid: object,
) -> None:
    payload = _payload(operation)
    payload[field] = invalid

    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope(operation, payload=payload))


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("container_engine",), "docker"),
        (("network_disabled",), False),
        (("minimum_free_bytes",), True),
        (("containers", 0, "local_path"), None),
        (("containers", 0, "file_sha256"), None),
        (("containers", 0, "extra_flags"), ["--bind=/"]),
        (("artifact_hashes", "execution_profile"), "f" * 64),
        (("project_hash",), "f" * 64),
        (("source_paths",), ["relative.fastq.gz"]),
        (("source_paths",), ["/srv/raw/a.fastq.gz", "/srv/raw/a.fastq.gz"]),
    ],
)
def test_preflight_nested_contract_is_strict(path: tuple[object, ...], invalid: object) -> None:
    payload = _preflight_payload()
    target: Any = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = invalid

    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope("preflight", payload=payload))


@pytest.mark.parametrize(
    ("source_host", "execution_host", "relation"),
    [
        ("host-1", "host-1", "shared"),
        ("host-1", "host-2", "same"),
    ],
)
def test_preflight_host_relation_must_exactly_match_host_identity(
    source_host: str,
    execution_host: str,
    relation: str,
) -> None:
    payload = _preflight_payload()
    payload.update(
        {
            "source_host": source_host,
            "execution_host": execution_host,
            "host_relation": relation,
        }
    )

    with pytest.raises(SchedulerProtocolError, match="host_relation conflicts"):
        parse_request(_envelope("preflight", payload=payload))


def test_same_host_without_mapping_requires_identical_ordered_paths() -> None:
    payload = _preflight_payload()
    payload["execution_paths"] = ["/srv/raw/different.fastq.gz"]

    with pytest.raises(SchedulerProtocolError, match="same-host paths must match"):
        parse_request(_envelope("preflight", payload=payload))


def test_shared_mapping_is_complete_ordered_and_uses_longest_prefix() -> None:
    request = parse_request(_envelope("preflight", payload=_shared_preflight_payload()))

    assert request.operation == "preflight"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_mapping",
        "uncovered_source",
        "different_lengths",
        "wrong_target",
        "wrong_order",
        "duplicate_source_prefix",
    ],
)
def test_shared_mapping_rejects_incomplete_ambiguous_or_misaligned_paths(
    mutation: str,
) -> None:
    payload = _shared_preflight_payload()
    mappings = payload["path_mapping"]
    assert isinstance(mappings, list)
    execution_paths = payload["execution_paths"]
    assert isinstance(execution_paths, list)
    if mutation == "missing_mapping":
        payload["path_mapping"] = []
    elif mutation == "uncovered_source":
        payload["path_mapping"] = [mappings[1]]
    elif mutation == "different_lengths":
        payload["execution_paths"] = execution_paths[:1]
    elif mutation == "wrong_target":
        execution_paths[0] = "/cluster/wrong/sample-a.fastq.gz"
    elif mutation == "wrong_order":
        payload["execution_paths"] = list(reversed(execution_paths))
    else:
        payload["path_mapping"] = [
            *mappings,
            {
                "source_prefix": "/source/project",
                "execution_prefix": "/cluster/ambiguous",
            },
        ]

    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope("preflight", payload=payload))


@pytest.mark.parametrize(
    "image",
    [
        "registry.example.org/team/tool:1.2.3",
        "registry.example.org:5000/team/sub_repo/tool:Tag_1-2",
        "quay.io/biocontainers/fastqc:0.12.1--0",
    ],
)
def test_preflight_accepts_explicit_safe_oci_tags(image: str) -> None:
    payload = _preflight_payload()
    containers = payload["containers"]
    assert isinstance(containers, list) and isinstance(containers[0], dict)
    containers[0]["image"] = image

    assert parse_request(_envelope("preflight", payload=payload)).operation == "preflight"


@pytest.mark.parametrize(
    "image",
    [
        "ubuntu:22.04",
        "https://registry.example.org/team/tool:1.0",
        f"registry.example.org/team/tool@sha256:{'8' * 64}",
        "registry.example.org/team/tool:latest",
        "registry.example.org/team/tool:bad tag",
        "registry.example.org/team/tool:tag;id",
        "registry.example.org/team/tool:$(id)",
        "registry.example.org/team/tool:`id`",
        "registry.example.org/team/tool:tag\nnext",
    ],
)
def test_preflight_rejects_unsafe_or_unpinned_oci_image_tokens(image: str) -> None:
    payload = _preflight_payload()
    containers = payload["containers"]
    assert isinstance(containers, list) and isinstance(containers[0], dict)
    containers[0]["image"] = image

    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope("preflight", payload=payload))


@pytest.mark.parametrize(
    "local_path",
    [
        "/srv/biopipe/cache/run-1/fastqc.img",
        "/srv/biopipe/cache/run-1/fastqc.SIF",
        "/srv/biopipe/cache/run-1/.sif",
        "/srv/biopipe/cache/run-1/fastqc.sif/child",
    ],
)
def test_preflight_requires_exact_lowercase_sif_leaf(local_path: str) -> None:
    payload = _preflight_payload()
    containers = payload["containers"]
    assert isinstance(containers, list) and isinstance(containers[0], dict)
    containers[0]["local_path"] = local_path

    with pytest.raises(SchedulerProtocolError, match=r"one \.sif file"):
        parse_request(_envelope("preflight", payload=payload))


def test_preflight_accepts_canonical_absolute_sif_outside_per_run_cache_dir() -> None:
    payload = _preflight_payload()
    containers = payload["containers"]
    assert isinstance(containers, list) and isinstance(containers[0], dict)
    containers[0]["local_path"] = "/srv/biopipe/shared-sif/fastqc.sif"

    assert parse_request(_envelope("preflight", payload=payload)).operation == "preflight"


def test_preflight_rejects_unpaired_unicode_surrogate_as_protocol_error() -> None:
    payload = _preflight_payload()
    payload["deploy_dir"] = "/srv/biopipe/\ud800"

    with pytest.raises(SchedulerProtocolError, match="bounded safe text"):
        parse_request(_envelope("preflight", payload=payload))


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("size", 1),
        ("content_base64", "***"),
        ("path", "../main.nf"),
        ("sha256", "F" * 64),
        ("sha256", "f" * 64),
        ("extra", True),
    ],
)
def test_deploy_file_contract_is_exact_and_content_bound(field: str, invalid: object) -> None:
    payload = _deploy_payload()
    file_record = payload["files"][0]  # type: ignore[index]
    if field == "extra":
        file_record[field] = invalid
    else:
        file_record[field] = invalid

    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope("deploy", payload=payload))


def test_deploy_rejects_noncanonical_base64_pad_bits() -> None:
    payload = _deploy_payload()
    file_record = payload["files"][0]  # type: ignore[index]
    canonical = file_record["content_base64"]
    assert isinstance(canonical, str) and canonical.endswith("Cg==")
    file_record["content_base64"] = canonical.removesuffix("Cg==") + "Ch=="
    assert base64.b64decode(file_record["content_base64"], validate=True) == b"synthetic\n"

    with pytest.raises(SchedulerProtocolError, match="not canonical"):
        parse_request(_envelope("deploy", payload=payload))


def test_deploy_bundle_hash_is_derived_from_canonical_file_metadata() -> None:
    payload = _deploy_payload()
    payload["bundle_hash"] = "c" * 64

    with pytest.raises(SchedulerProtocolError, match="do not match bundle_hash"):
        parse_request(_envelope("deploy", payload=payload))


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("approved",), False),
        (("signature",), "D" * 64),
        (("extra",), "unsafe"),
        (("artifact_hashes", "execution_profile"), "f" * 64),
        (("artifact_hashes", "dataset_manifest"), "f" * 64),
        (("bundle_hash",), "f" * 64),
        (("compatibility_hash",), "f" * 64),
        (("approved_at",), "2026-07-19T12:30:00"),
    ],
)
def test_approval_contract_and_hash_bindings_are_strict(
    path: tuple[str, ...],
    invalid: object,
) -> None:
    payload = _submit_payload()
    target: Any = payload["approval"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = invalid

    with pytest.raises(SchedulerProtocolError):
        parse_request(_envelope("submit", payload=payload))


@pytest.mark.parametrize("operation", ["submit", "resume"])
def test_hmac_material_is_canonical_literal_v2_and_covers_scheduler_binding(
    operation: str,
) -> None:
    request = parse_request(_envelope(operation, request_id="transport-A"))
    material = canonical_hmac_envelope_bytes(request)
    decoded = json.loads(material)

    assert decoded["protocol_version"] == "2.0"
    assert decoded["operation"] == operation
    assert "request_id" not in decoded
    assert decoded["payload"]["scheduler_policy_hash"] == _POLICY_HASH
    assert "signature" not in decoded["payload"]["approval"]
    assert decoded["payload"]["approval"]["key_id"] == "controller-key-1"
    assert material == json.dumps(
        decoded,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    assert b"operator-\\u4e00" in material


def test_hmac_material_separates_versions_operations_and_transport_request_ids() -> None:
    first = parse_request(_envelope("submit", request_id="transport-A"))
    second = parse_request(_envelope("submit", request_id="transport-B"))
    resumed = parse_request(_envelope("resume", request_id="transport-A"))
    v2 = canonical_hmac_envelope_bytes(first)

    assert canonical_hmac_envelope_bytes(second) == v2
    assert canonical_hmac_envelope_bytes(resumed) != v2
    v1_value = json.loads(v2)
    v1_value["protocol_version"] = "1.0"
    v1 = json.dumps(
        v1_value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    key = b"scheduler-protocol-test-key"
    assert v1 != v2
    assert hmac.new(key, v1, hashlib.sha256).digest() != hmac.new(key, v2, hashlib.sha256).digest()


def test_hmac_material_changes_when_policy_binding_changes() -> None:
    original = parse_request(_envelope("submit"))
    changed_payload = _submit_payload()
    changed_payload["scheduler_policy_hash"] = "9" * 64
    changed = parse_request(_envelope("submit", payload=changed_payload))

    assert canonical_hmac_envelope_bytes(original) != canonical_hmac_envelope_bytes(changed)


@pytest.mark.parametrize("operation", ["health", "preflight", "deploy", "status"])
def test_only_submit_and_resume_have_hmac_material(operation: str) -> None:
    with pytest.raises(SchedulerProtocolError):
        canonical_hmac_envelope_bytes(parse_request(_envelope(operation)))


def test_wire_decoder_rejects_duplicates_nonfinite_and_excessive_nesting() -> None:
    valid = json.dumps(_envelope("health"), separators=(",", ":")).encode()
    assert parse_request(decode_json_line(valid)).operation == "health"

    invalid = [
        b'{"value":1,"value":2}',
        b'{"value":NaN}',
        b"[" * 129 + b"0" + b"]" * 129,
        b"\xff",
        b"",
    ]
    for payload in invalid:
        with pytest.raises(SchedulerProtocolError):
            decode_json_line(payload)


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        (
            {},
            SlurmRunEvidence(
                job_id="12345",
                submission_marker=_MARKER,
                submitted_at="2026-07-19T12:34:56",
                batch_script_sha256=_SCRIPT_HASH,
                scheduler_policy_hash=_POLICY_HASH,
                raw_state="RUNNING",
                mapped_state="active",
                reason_code="SLURM_RUNNING",
                exit_code=None,
                signal=None,
                source="squeue",
            ),
        ),
        (
            {
                "raw_state": "COMPLETED",
                "mapped_state": "succeeded",
                "reason_code": "SLURM_COMPLETED",
                "exit_code": 0,
                "signal": 0,
                "source": "sacct",
            },
            None,
        ),
        (
            {
                "raw_state": "CANCELLED by 123",
                "mapped_state": "failed",
                "reason_code": "SLURM_CANCELLED",
                "exit_code": 0,
                "signal": 15,
                "source": "sacct",
            },
            None,
        ),
        (
            {
                "raw_state": None,
                "mapped_state": "indeterminate",
                "reason_code": "SLURM_OBSERVATION_MISSING",
                "source": "reconciled",
            },
            None,
        ),
    ],
)
def test_slurm_evidence_represents_active_terminal_and_indeterminate_states(
    updates: dict[str, object],
    expected: SlurmRunEvidence | None,
) -> None:
    evidence = parse_slurm_run_evidence(_evidence(**updates))

    assert evidence == (expected or SlurmRunEvidence(**_evidence(**updates)))


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("job_id", "0"),
        ("job_id", "12345.batch"),
        ("submission_marker", "E" * 64),
        ("submission_marker", "0" * 64),
        ("submitted_at", "2026-07-19T12:34:56Z"),
        ("submitted_at", "2026-02-30T12:34:56"),
        ("batch_script_sha256", "f" * 63),
        ("scheduler_policy_hash", "0" * 64),
        ("raw_state", "CANCELLED+"),
        ("raw_state", "running"),
        ("mapped_state", "completed"),
        ("reason_code", "scheduler missing"),
        ("exit_code", True),
        ("signal", 256),
        ("source", "sbatch"),
    ],
)
def test_slurm_evidence_rejects_malformed_identity_and_state_fields(
    field: str,
    invalid: object,
) -> None:
    with pytest.raises(SchedulerProtocolError):
        parse_slurm_run_evidence(_evidence(**{field: invalid}))


@pytest.mark.parametrize(
    "updates",
    [
        {"exit_code": 1, "signal": None},
        {"source": "squeue", "exit_code": 1, "signal": 0},
        {"raw_state": None},
        {"raw_state": None, "mapped_state": "indeterminate"},
        {
            "raw_state": "FAILED",
            "mapped_state": "succeeded",
            "exit_code": 0,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "COMPLETED",
            "mapped_state": "succeeded",
            "exit_code": 1,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "FAILED",
            "mapped_state": "failed",
            "exit_code": 0,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "COMPLETED",
            "mapped_state": "failed",
            "reason_code": "SLURM_FAILED",
            "exit_code": 1,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "COMPLETED",
            "mapped_state": "active",
            "reason_code": "SLURM_RUNNING",
            "exit_code": 0,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "FAILED",
            "mapped_state": "queued",
            "reason_code": "SLURM_PENDING",
            "exit_code": 1,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "RUNNING",
            "mapped_state": "failed",
            "reason_code": "SLURM_FAILED",
            "exit_code": 1,
            "signal": 0,
            "source": "sacct",
        },
        {
            "raw_state": "MADE_UP_STATE",
            "mapped_state": "active",
            "reason_code": "SLURM_RUNNING",
        },
        {
            "raw_state": "RUNNING",
            "mapped_state": "active",
            "reason_code": "SLURM_PENDING",
        },
        {
            "raw_state": "CANCELLED by 123",
            "mapped_state": "indeterminate",
            "reason_code": "SLURM_TERMINAL_REQUIRES_SACCT",
        },
        {
            "raw_state": "RUNNING",
            "mapped_state": "indeterminate",
            "reason_code": "SLURM_OBSERVATION_CONFLICT",
            "source": "reconciled",
        },
        {
            "raw_state": None,
            "mapped_state": "indeterminate",
            "reason_code": "SLURM_ARBITRARY",
            "source": "reconciled",
        },
    ],
)
def test_slurm_evidence_rejects_cross_field_conflicts(updates: dict[str, object]) -> None:
    with pytest.raises(SchedulerProtocolError):
        parse_slurm_run_evidence(_evidence(**updates))


def test_slurm_evidence_requires_every_exact_field() -> None:
    record = _evidence()
    for field in record:
        missing = dict(record)
        del missing[field]
        with pytest.raises(SchedulerProtocolError, match="exact contract"):
            parse_slurm_run_evidence(missing)

    with pytest.raises(SchedulerProtocolError, match="exact contract"):
        parse_slurm_run_evidence({**record, "cluster": "all"})


def test_scheduler_protocol_uses_only_stdlib_and_pure_slurm_contract_imports() -> None:
    source_path = Path(__file__).parents[1] / "src" / "bioexec" / "scheduler_protocol.py"
    syntax = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    allowed_roots = {
        "__future__",
        "base64",
        "binascii",
        "collections",
        "dataclasses",
        "datetime",
        "hashlib",
        "json",
        "pathlib",
        "re",
        "types",
        "typing",
    }
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".", 1)[0] in allowed_roots for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 1:
                assert node.module == "slurm"
            else:
                assert node.level == 0
                assert node.module is not None
                assert node.module.split(".", 1)[0] in allowed_roots


@pytest.mark.parametrize(
    "source_path",
    [
        "remote_executor/src/bioexec/main.py",
        "remote_executor/src/bioexec/protocol.py",
        "remote_executor/src/bioexec/config.py",
        "remote_executor/src/bioexec/preflight.py",
        "remote_executor/src/bioexec/deployment.py",
        "remote_executor/src/bioexec/runner.py",
        "src/biopipe/execution/client.py",
        "src/biopipe/execution/signing.py",
    ],
)
def test_scheduler_protocol_is_not_imported_by_v1_production_paths(
    source_path: str,
) -> None:
    path = Path(__file__).parents[2] / source_path
    syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all(not alias.name.endswith("scheduler_protocol") for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or not node.module.endswith("scheduler_protocol")


def test_scheduler_protocol_contract_performs_no_external_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("dormant protocol contract performed an external operation")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    request = parse_request(_envelope("submit"))
    assert canonical_hmac_envelope_bytes(request)
    assert (
        parse_slurm_run_evidence(
            _evidence(
                raw_state=None,
                mapped_state="indeterminate",
                reason_code="SLURM_OBSERVATION_MISSING",
                source="reconciled",
            )
        ).mapped_state
        == "indeterminate"
    )
