"""Offline adversarial tests for the dormant M7.0c compute preflight."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_preflight as scheduler_preflight_module
from bioexec.scheduler_preflight import (
    COMPUTE_CHECK_NAMES,
    ComputePreflightManifest,
    SchedulerPreflightError,
    SchedulerPreflightState,
    canonical_evidence_bytes,
    canonical_manifest_bytes,
    consume_capability,
    decode_compute_evidence,
    evidence_hash,
    input_set_hash,
    issue_capability,
    manifest_hash,
    parse_compute_evidence,
    parse_compute_manifest,
    preflight_result,
    prepare_preflight,
    record_clock_discontinuity,
    record_compute_evidence,
    record_driver_timeout,
    record_held_release,
    record_held_submission,
    record_release_intent,
    record_release_unknown,
    record_scheduler_poll,
    record_submit_unknown,
    render_compute_template,
    template_hash,
)
from bioexec.slurm import (
    SlurmHeldJob,
    SlurmJobRef,
    SlurmObservation,
    SlurmSchedulerPolicy,
    scheduler_policy_hash,
)

_PROFILE_HASH = "a" * 64
_POLICY_HASH_PLACEHOLDER = "b" * 64
_WORKER_HASH = "c" * 64
_TOKEN = "e" * 64
_TOKEN_HASH = hashlib.sha256(_TOKEN.encode("ascii")).hexdigest()
_CONSUMER_BINDING_HASH = "d" * 64
_SUBMITTED_AT = "2026-07-19T12:34:56"
_JOB_ID = "12345"


def _canonical_hash(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _policy_mapping(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "partition": "compute",
        "account": "bioinfo",
        "qos": "normal",
        "time_limit": "00:15:00",
        "cpus_per_task": 8,
        "memory_mib": 16_384,
        "submit_timeout_seconds": 60,
        "status_poll_seconds": 5,
        "max_pending_seconds": 60,
    }
    value.update(updates)
    return value


def _artifact_hashes() -> dict[str, str]:
    return {
        "dataset_manifest": "1" * 64,
        "pipeline_spec": "2" * 64,
        "execution_plan": "3" * 64,
        "software_lock": "4" * 64,
        "execution_profile": _PROFILE_HASH,
    }


def _project_hash() -> str:
    hashes = _artifact_hashes()
    return _canonical_hash(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        }
    )


def _manifest_mapping(**updates: object) -> dict[str, Any]:
    policy_mapping = _policy_mapping()
    policy = SlurmSchedulerPolicy.from_mapping(policy_mapping)
    execution_paths = ("/shared/raw/sample_R1.fastq.gz",)
    value: dict[str, Any] = {
        "manifest_version": "1.1",
        "preflight_id": "preflight-1",
        "profile_version": "2.0",
        "profile_id": "hpc01-slurm",
        "profile_hash": _PROFILE_HASH,
        "scheduler_policy_hash": scheduler_policy_hash(policy),
        "scheduler_policy": policy_mapping,
        "compute_runtime": {
            "python_executable": "/usr/bin/python3",
            "python_sha256": "9" * 64,
            "java_executable": "/usr/bin/java",
            "java_sha256": "a" * 64,
            "nextflow_executable": "/opt/nextflow/bin/nextflow",
            "nextflow_sha256": "b" * 64,
            "nextflow_version": "24.10.0",
            "nextflow_jar": "/opt/nextflow/lib/nextflow-24.10.0-one.jar",
            "nextflow_jar_sha256": "c" * 64,
            "apptainer_executable": "/usr/bin/apptainer",
            "apptainer_sha256": "e" * 64,
            "command_timeout_seconds": 30.0,
            "max_command_output_bytes": 262144,
        },
        "project_hash": _project_hash(),
        "artifact_hashes": _artifact_hashes(),
        "source_host": "source-host",
        "execution_host": "compute-host",
        "host_relation": "shared",
        "source_paths": ["/source/raw/sample_R1.fastq.gz"],
        "execution_paths": list(execution_paths),
        "path_mapping": [
            {
                "source_prefix": "/source/raw",
                "execution_prefix": "/shared/raw",
            }
        ],
        "input_set_hash": input_set_hash(execution_paths),
        "deploy_dir": "/shared/deploy/project-1",
        "work_dir": "/shared/work/run-1",
        "output_dir": "/shared/results/run-1",
        "cache_dir": "/shared/cache/job-1",
        "containers": [
            {
                "name": "fastqc",
                "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
                "digest": f"sha256:{'5' * 64}",
                "local_path": "/shared/cache/images/fastqc.sif",
                "file_sha256": "6" * 64,
            },
            {
                "name": "multiqc",
                "image": "quay.io/biocontainers/multiqc:1.27.1--pyhdfd78af_0",
                "digest": f"sha256:{'7' * 64}",
                "local_path": "/shared/cache/images/multiqc.sif",
                "file_sha256": "8" * 64,
            },
        ],
        "minimum_free_bytes": 1024 * 1024,
        "network_disabled": True,
        "resume_run_id": None,
        "resume_directory_identities": None,
        "preflight_ttl_seconds": 900,
        "worker": {
            "contract_version": "1.0",
            "executable": "/opt/biopipe/bin/bioexec-compute-preflight",
            "executable_sha256": _WORKER_HASH,
            "manifest_path": "/private/preflight-1/manifest.json",
            "evidence_path": "/private/preflight-1/evidence.json",
        },
    }
    value.update(updates)
    return value


def _manifest() -> ComputePreflightManifest:
    return parse_compute_manifest(_manifest_mapping())


def _checks(*, failed: str | None = None) -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "status": "failed" if name == failed else "passed",
            "code": "PATH_UNAVAILABLE" if name == failed else "OK",
            "evidence_sha256": hashlib.sha256(f"evidence:{name}".encode()).hexdigest(),
        }
        for name in COMPUTE_CHECK_NAMES
    ]


def _job(state: SchedulerPreflightState) -> SlurmJobRef:
    assert state.job is not None
    return state.job


def _prepared() -> SchedulerPreflightState:
    return prepare_preflight(_manifest())


def _held_job(state: SchedulerPreflightState) -> SlurmHeldJob:
    return SlurmHeldJob(
        job=SlurmJobRef(
            job_id=_JOB_ID,
            submission_marker=state.submission_marker,
            submitted_at=_SUBMITTED_AT,
        ),
        state="PENDING",
        reason="JobHeldUser",
    )


def _polling() -> SchedulerPreflightState:
    prepared = _prepared()
    held = record_held_submission(prepared, _held_job(prepared))
    release_ready = record_release_intent(held, elapsed_seconds=0)
    return record_held_release(release_ready)


def _awaiting_evidence() -> SchedulerPreflightState:
    polling = _polling()
    accounting = SlurmObservation(
        source="sacct",
        job=_job(polling),
        state="COMPLETED",
        exit_code=(0, 0),
    )
    return record_scheduler_poll(
        polling,
        queue=None,
        accounting=accounting,
        elapsed_seconds=10,
    )


def _evidence_mapping(
    state: SchedulerPreflightState,
    *,
    failed: str | None = None,
    **updates: object,
) -> dict[str, Any]:
    job = _job(state)
    value: dict[str, Any] = {
        "evidence_version": "1.0",
        "preflight_id": state.manifest.preflight_id,
        "profile_id": state.manifest.profile_id,
        "profile_hash": state.manifest.profile_hash,
        "scheduler_policy_hash": state.manifest.scheduler_policy_hash,
        "project_hash": state.manifest.project_hash,
        "input_set_hash": state.manifest.input_set_hash,
        "manifest_sha256": state.manifest_sha256,
        "worker_sha256": state.manifest.worker.executable_sha256,
        "job_id": job.job_id,
        "submission_marker": job.submission_marker,
        "status": "failed" if failed is not None else "passed",
        "checks": _checks(failed=failed),
    }
    value.update(updates)
    return value


def _candidate() -> SchedulerPreflightState:
    state = _awaiting_evidence()
    return record_compute_evidence(state, _evidence_mapping(state), elapsed_seconds=11)


def _passed() -> SchedulerPreflightState:
    return issue_capability(
        _candidate(),
        token_hash=_TOKEN_HASH,
        elapsed_seconds=12,
    )


def _queue(state: SchedulerPreflightState, raw_state: str) -> SlurmObservation:
    return SlurmObservation(source="squeue", job=_job(state), state=raw_state)


def _accounting(
    state: SchedulerPreflightState,
    raw_state: str,
    exit_code: tuple[int, int] | None,
) -> SlurmObservation:
    return SlurmObservation(
        source="sacct",
        job=_job(state),
        state=raw_state,
        exit_code=exit_code,
    )


def test_exact_manifest_is_immutable_canonical_and_policy_bound() -> None:
    value = _manifest_mapping()
    reordered = {key: value[key] for key in reversed(value)}

    first = parse_compute_manifest(value)
    second = parse_compute_manifest(reordered)

    assert first == second
    assert canonical_manifest_bytes(first) == canonical_manifest_bytes(second)
    assert manifest_hash(first) == hashlib.sha256(canonical_manifest_bytes(first)).hexdigest()
    assert first.scheduler_policy_hash == scheduler_policy_hash(first.scheduler_policy)
    with pytest.raises(TypeError):
        first.artifact_hashes["dataset_manifest"] = "f" * 64  # type: ignore[index]


@pytest.mark.parametrize("field", sorted(_manifest_mapping()))
def test_manifest_requires_every_exact_field(field: str) -> None:
    value = _manifest_mapping()
    del value[field]

    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(value)


@pytest.mark.parametrize(
    "forbidden",
    [
        "job_id",
        "submission_marker",
        "submitted_at",
        "script",
        "script_bytes",
        "script_path",
        "argv",
        "sbatch_argv",
        "flags",
        "extra_flags",
        "command",
        "shell",
    ],
)
def test_manifest_rejects_every_caller_scheduler_or_script_surface(forbidden: str) -> None:
    value = _manifest_mapping()
    value[forbidden] = "attacker supplied"

    with pytest.raises(SchedulerPreflightError, match="exact contract"):
        parse_compute_manifest(value)


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("manifest_version",), "2.0"),
        (("profile_version",), "1.0"),
        (("scheduler_policy_hash",), _POLICY_HASH_PLACEHOLDER),
        (("scheduler_policy", "extra_flags"), ["--wrap=id"]),
        (("artifact_hashes", "execution_profile"), "f" * 64),
        (("project_hash",), "f" * 64),
        (("host_relation",), "same"),
        (("input_set_hash",), "f" * 64),
        (("network_disabled",), False),
        (("minimum_free_bytes",), True),
        (("preflight_ttl_seconds",), 0),
        (("compute_runtime", "python_executable"), "/usr/bin/python"),
        (("compute_runtime", "python_sha256"), "0" * 64),
        (("compute_runtime", "java_executable"), "/usr/bin/sh"),
        (("compute_runtime", "nextflow_version"), "bad version"),
        (("compute_runtime", "apptainer_executable"), "/usr/bin/apptainer;id"),
        (("compute_runtime", "command_timeout_seconds"), float("nan")),
        (("compute_runtime", "max_command_output_bytes"), True),
        (("worker", "contract_version"), "2.0"),
        (("worker", "executable_sha256"), "0" * 64),
        (("worker", "executable"), "/bin/sh"),
        (("worker", "manifest_path"), "/private/manifest;id/manifest.json"),
        (("worker", "evidence_path"), "/private/preflight-1/manifest.json"),
    ],
)
def test_manifest_bindings_and_trusted_worker_fail_closed(
    path: tuple[str, ...],
    invalid: object,
) -> None:
    value = _manifest_mapping()
    target: dict[str, Any] = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid

    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(value)


def test_resume_requires_all_exact_private_directory_identities() -> None:
    identity = {
        "device": 1,
        "inode": 2,
        "owner": os.geteuid(),
        "group": os.getegid(),
        "mode": 0o700,
    }
    value = _manifest_mapping(
        resume_run_id="run-previous",
        resume_directory_identities={
            "deploy": dict(identity),
            "work": dict(identity),
            "output": dict(identity),
        },
    )
    manifest = parse_compute_manifest(value)
    assert manifest.resume_run_id == "run-previous"
    assert manifest.resume_directory_identities is not None
    assert set(manifest.resume_directory_identities) == {"deploy", "work", "output"}

    missing = copy.deepcopy(value)
    del missing["resume_directory_identities"]["output"]
    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(missing)

    wrong_mode = copy.deepcopy(value)
    wrong_mode["resume_directory_identities"]["work"]["mode"] = 0o750
    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(wrong_mode)

    initial_with_identity = _manifest_mapping(
        resume_directory_identities=value["resume_directory_identities"]
    )
    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(initial_with_identity)

    resume_without_identity = _manifest_mapping(resume_run_id="run-previous")
    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(resume_without_identity)


@pytest.mark.parametrize(
    ("location", "invalid"),
    [
        ("host_relation", []),
        ("containers.digest", 123),
        ("containers.name", None),
        ("worker.executable", []),
    ],
)
def test_manifest_wrong_json_types_raise_only_contract_errors(
    location: str,
    invalid: object,
) -> None:
    value = _manifest_mapping()
    if location.startswith("containers."):
        value["containers"][0][location.split(".", 1)[1]] = invalid
    elif location.startswith("worker."):
        value["worker"][location.split(".", 1)[1]] = invalid
    else:
        value[location] = invalid

    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(value)


def test_manifest_rejects_unpaired_unicode_surrogate_as_contract_error() -> None:
    value = _manifest_mapping(deploy_dir="/shared/deploy/\ud800")

    with pytest.raises(SchedulerPreflightError, match="bounded safe text"):
        parse_compute_manifest(value)


def test_manifest_rejects_missing_worker_before_template_generation() -> None:
    value = _manifest_mapping()
    del value["worker"]

    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(value)
    with pytest.raises(SchedulerPreflightError):
        render_compute_template(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "mutation",
    [
        {"execution_paths": ["/shared/raw/other.fastq.gz"]},
        {"path_mapping": []},
        {"path_mapping": [{"source_prefix": "/source/raw", "execution_prefix": "/wrong/raw"}]},
        {"source_paths": ["/source/raw/a.fastq.gz", "/source/raw/b.fastq.gz"]},
    ],
)
def test_manifest_path_mapping_and_input_identity_are_exact(mutation: dict[str, object]) -> None:
    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(_manifest_mapping(**mutation))


def test_manifest_rejects_duplicate_source_prefix_even_with_different_targets() -> None:
    value = _manifest_mapping()
    value["path_mapping"].append({"source_prefix": "/source/raw", "execution_prefix": "/other/raw"})

    with pytest.raises(SchedulerPreflightError, match="source_prefix values must be unique"):
        parse_compute_manifest(value)


@pytest.mark.parametrize(
    "image",
    [
        "ubuntu:22.04",
        "https://registry.example.org/team/tool:1.0",
        f"registry.example.org/team/tool@sha256:{'8' * 64}",
        "registry.example.org/team/tool:latest",
        "registry.example.org/team/tool:tag;id",
        "registry.example.org/team/tool:$(id)",
    ],
)
def test_manifest_rejects_unsafe_or_unpinned_container_image(image: str) -> None:
    value = _manifest_mapping()
    value["containers"][0]["image"] = image

    with pytest.raises(SchedulerPreflightError):
        parse_compute_manifest(value)


@pytest.mark.parametrize(
    "local_path",
    [
        "/shared/cache/images/fastqc.img",
        "/shared/cache/images/fastqc.SIF",
        "/shared/cache/images/.sif",
        "/shared/cache/images/fastqc.sif/child",
    ],
)
def test_manifest_requires_canonical_lowercase_sif_leaf(local_path: str) -> None:
    value = _manifest_mapping()
    value["containers"][0]["local_path"] = local_path

    with pytest.raises(SchedulerPreflightError, match=r"one \.sif file"):
        parse_compute_manifest(value)


def test_template_is_fixed_ascii_worker_invocation_and_hash_bound() -> None:
    manifest = _manifest()
    rendered = render_compute_template(manifest)

    expected = (
        "#!/bin/sh\n"
        "set -eu\n"
        "umask 077\n"
        "exec /usr/bin/python3 -I -S /opt/biopipe/bin/bioexec-compute-preflight \\\n"
        "  --contract-version=1.0 \\\n"
        "  --manifest=/private/preflight-1/manifest.json \\\n"
        f"  --manifest-sha256={manifest_hash(manifest)} \\\n"
        f"  --worker-sha256={_WORKER_HASH} \\\n"
        "  --evidence=/private/preflight-1/evidence.json\n"
    ).encode("ascii")
    assert rendered == expected
    assert template_hash(manifest) == hashlib.sha256(rendered).hexdigest()
    assert b"#SBATCH" not in rendered
    assert b"--wrap" not in rendered
    assert b"scancel" not in rendered
    assert b"/source/raw" not in rendered
    assert b"/shared/raw" not in rendered
    assert b"eval" not in rendered


def test_template_identity_changes_with_manifest_but_not_mapping_key_order() -> None:
    first_value = _manifest_mapping()
    reordered = {key: first_value[key] for key in reversed(first_value)}
    changed = _manifest_mapping(minimum_free_bytes=2 * 1024 * 1024)

    assert render_compute_template(parse_compute_manifest(first_value)) == render_compute_template(
        parse_compute_manifest(reordered)
    )
    assert template_hash(parse_compute_manifest(first_value)) != template_hash(
        parse_compute_manifest(changed)
    )


def test_prepare_generates_script_and_domain_separated_marker_without_input() -> None:
    signature = inspect.signature(prepare_preflight)
    assert "script" not in signature.parameters
    assert "argv" not in signature.parameters
    assert "marker" not in " ".join(signature.parameters)
    state = _prepared()
    expected_marker = hashlib.sha256(
        b"easy-pipe:m7.0c:compute-preflight-marker:v1\x00"
        + bytes.fromhex(state.manifest_sha256)
        + bytes.fromhex(state.template_sha256)
    ).hexdigest()

    assert state.phase == "prepared"
    assert state.template_bytes == render_compute_template(state.manifest)
    assert state.submission_marker == expected_marker
    assert _prepared().submission_marker == state.submission_marker


def test_evidence_parser_requires_all_twelve_checks_and_derives_pass() -> None:
    state = _awaiting_evidence()
    value = _evidence_mapping(state)

    evidence = parse_compute_evidence(value)

    assert evidence.status == "passed"
    assert tuple(check.name for check in evidence.checks) == COMPUTE_CHECK_NAMES
    assert len(evidence.checks) == 12
    assert canonical_evidence_bytes(evidence) == json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    assert evidence_hash(evidence) == hashlib.sha256(canonical_evidence_bytes(evidence)).hexdigest()


@pytest.mark.parametrize("field", sorted(_evidence_mapping(_awaiting_evidence())))
def test_evidence_requires_every_exact_field(field: str) -> None:
    value = _evidence_mapping(_awaiting_evidence())
    del value[field]

    with pytest.raises(SchedulerPreflightError):
        parse_compute_evidence(value)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "duplicate",
        "reordered",
        "unknown",
    ],
)
def test_evidence_check_set_is_exact_ordered_and_duplicate_free(mutation: str) -> None:
    state = _awaiting_evidence()
    value = _evidence_mapping(state)
    checks = value["checks"]
    assert isinstance(checks, list)
    if mutation == "missing":
        checks.pop()
    elif mutation == "extra":
        checks.append(dict(checks[-1]))
    elif mutation == "duplicate":
        checks[1] = dict(checks[0])
    elif mutation == "reordered":
        checks[0], checks[1] = checks[1], checks[0]
    else:
        checks[0] = {**checks[0], "name": "arbitrary_check"}

    with pytest.raises(SchedulerPreflightError):
        parse_compute_evidence(value)


@pytest.mark.parametrize(
    ("status", "code", "top_status"),
    [
        ("failed", "OK", "failed"),
        ("passed", "PATH_UNAVAILABLE", "passed"),
        ("passed", "OK", "failed"),
        ("unknown", "OK", "failed"),
        ("passed", "bad code", "passed"),
    ],
)
def test_evidence_cannot_claim_pass_inconsistently(
    status: str,
    code: str,
    top_status: str,
) -> None:
    value = _evidence_mapping(_awaiting_evidence())
    value["checks"][0]["status"] = status
    value["checks"][0]["code"] = code
    value["status"] = top_status

    with pytest.raises(SchedulerPreflightError):
        parse_compute_evidence(value)


@pytest.mark.parametrize(
    ("location", "invalid"),
    [
        ("status", []),
        ("checks.status", []),
        ("checks.code", 1),
        ("checks.evidence_sha256", False),
        ("job_id", 12345),
    ],
)
def test_evidence_wrong_json_types_raise_only_contract_errors(
    location: str,
    invalid: object,
) -> None:
    value = _evidence_mapping(_awaiting_evidence())
    if location.startswith("checks."):
        value["checks"][0][location.split(".", 1)[1]] = invalid
    else:
        value[location] = invalid

    with pytest.raises(SchedulerPreflightError):
        parse_compute_evidence(value)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("job_id", "12345.batch"),
        ("submission_marker", "0" * 64),
        ("manifest_sha256", "0" * 64),
        ("worker_sha256", "A" * 64),
    ],
)
def test_evidence_rejects_malformed_job_and_digest_bindings(field: str, invalid: object) -> None:
    value = _evidence_mapping(_awaiting_evidence())
    value[field] = invalid

    with pytest.raises(SchedulerPreflightError):
        parse_compute_evidence(value)


@pytest.mark.parametrize("unobservable", ["submitted_at", "template_sha256"])
def test_raw_worker_evidence_rejects_remote_adapter_only_fields(unobservable: str) -> None:
    value = _evidence_mapping(_awaiting_evidence())
    value[unobservable] = _SUBMITTED_AT if unobservable == "submitted_at" else "f" * 64

    with pytest.raises(SchedulerPreflightError, match="exact contract"):
        parse_compute_evidence(value)


def test_evidence_decoder_rejects_duplicate_nonfinite_nested_and_oversized_json() -> None:
    state = _awaiting_evidence()
    encoded = json.dumps(_evidence_mapping(state), separators=(",", ":")).encode()
    assert decode_compute_evidence(encoded).status == "passed"

    with pytest.raises(SchedulerPreflightError):
        decode_compute_evidence(b'{"evidence_version":"1.0","evidence_version":"1.0"}')
    with pytest.raises(SchedulerPreflightError):
        decode_compute_evidence(b'{"value":NaN}')
    with pytest.raises(SchedulerPreflightError):
        decode_compute_evidence((b"[" * 129) + b"0" + (b"]" * 129))
    with pytest.raises(SchedulerPreflightError):
        decode_compute_evidence(b"x" * (256 * 1024 + 1))
    with pytest.raises(SchedulerPreflightError):
        decode_compute_evidence(b"\xff")


def test_happy_transcript_mints_and_consumes_one_bound_capability() -> None:
    state = _prepared()
    state = record_held_submission(state, _held_job(state))
    assert state.phase == "held" and state.job is not None
    assert state.held_job is not None and state.held_job.job == state.job
    state = record_release_intent(state, elapsed_seconds=1)
    assert state.phase == "release_ready"
    state = record_held_release(state)
    assert state.phase == "polling"

    state = record_scheduler_poll(
        state,
        queue=_queue(state, "PENDING"),
        accounting=None,
        elapsed_seconds=5,
    )
    assert state.phase == "polling" and state.reason_code == "SLURM_PENDING"
    state = record_scheduler_poll(
        state,
        queue=_queue(state, "RUNNING"),
        accounting=None,
        elapsed_seconds=10,
    )
    assert state.phase == "polling" and state.reason_code == "SLURM_RUNNING"
    state = record_scheduler_poll(
        state,
        queue=None,
        accounting=_accounting(state, "COMPLETED", (0, 0)),
        elapsed_seconds=15,
    )
    assert state.phase == "awaiting_evidence"
    assert state.terminal_observation is not None
    assert state.terminal_observation.source == "sacct"
    assert state.terminal_observation.exit_code == (0, 0)

    state = record_compute_evidence(state, _evidence_mapping(state), elapsed_seconds=16)
    assert state.phase == "candidate"
    assert preflight_result(state)["preflight_token"] is None
    state = issue_capability(
        state,
        token_hash=_TOKEN_HASH,
        elapsed_seconds=17,
    )
    result = preflight_result(state)
    assert result["status"] == "passed"
    assert result["preflight_token"] is None
    assert state.capability is not None
    assert not hasattr(state.capability, "token")
    assert _TOKEN not in repr(state.capability)
    record = state.capability.as_record()
    assert "token" not in record
    assert _TOKEN not in json.dumps(record)
    assert record["consumed"] is False

    consumed = consume_capability(
        state,
        token=_TOKEN,
        consumed_by="run-1",
        consumer_binding_hash=_CONSUMER_BINDING_HASH,
        elapsed_seconds=18,
    )
    assert consumed.capability is not None and consumed.capability.consumed is True
    assert preflight_result(consumed)["preflight_token"] is None
    with pytest.raises(SchedulerPreflightError, match="already consumed"):
        consume_capability(
            consumed,
            token=_TOKEN,
            consumed_by="run-2",
            consumer_binding_hash="f" * 64,
            elapsed_seconds=19,
        )


def test_held_transition_requires_exact_validated_user_hold_evidence() -> None:
    state = _prepared()
    with pytest.raises(SchedulerPreflightError, match="validated user-hold"):
        record_held_submission(state, _held_job(state).job)  # type: ignore[arg-type]

    wrong = SlurmHeldJob(
        job=SlurmJobRef(
            job_id=_JOB_ID,
            submission_marker="f" * 64,
            submitted_at=_SUBMITTED_AT,
        ),
        state="PENDING",
        reason="JobHeldUser",
    )
    with pytest.raises(SchedulerPreflightError, match="marker does not bind"):
        record_held_submission(state, wrong)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_hold",
        "missing_terminal",
        "evidence_hash",
        "template_hash",
        "not_started",
        "terminal_flag",
    ],
)
def test_capability_gate_rechecks_persisted_success_bindings(mutation: str) -> None:
    state = copy.copy(_candidate())
    if mutation == "missing_hold":
        object.__setattr__(state, "held_job", None)
    elif mutation == "missing_terminal":
        object.__setattr__(state, "terminal_observation", None)
    elif mutation == "evidence_hash":
        object.__setattr__(state, "evidence_sha256", "f" * 64)
    elif mutation == "template_hash":
        object.__setattr__(state, "template_sha256", "f" * 64)
    elif mutation == "not_started":
        object.__setattr__(state, "started", False)
    else:
        object.__setattr__(state, "terminal_seen", False)

    with pytest.raises(SchedulerPreflightError):
        issue_capability(
            state,
            token_hash=_TOKEN_HASH,
            elapsed_seconds=12,
        )


def test_passed_result_and_consume_reject_corrupted_capability_record() -> None:
    state = copy.copy(_passed())
    assert state.capability is not None
    capability = copy.copy(state.capability)
    object.__setattr__(capability, "binding_hash", "f" * 64)
    object.__setattr__(state, "capability", capability)

    with pytest.raises(SchedulerPreflightError, match="does not bind"):
        preflight_result(state)
    with pytest.raises(SchedulerPreflightError, match="does not bind"):
        consume_capability(
            state,
            token=_TOKEN,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
            elapsed_seconds=13,
        )


def test_public_dataclass_replace_cannot_reconstruct_state_or_capability() -> None:
    state = _passed()
    assert state.capability is not None

    with pytest.raises((TypeError, ValueError)):
        replace(state, phase="candidate")
    with pytest.raises((TypeError, ValueError)):
        replace(state.capability, consumed=False)


@pytest.mark.parametrize("mutation", ["token", "window", "consumed_reset"])
def test_grant_binding_rejects_token_window_and_consumption_reconstruction(
    mutation: str,
) -> None:
    if mutation == "consumed_reset":
        state = consume_capability(
            _passed(),
            token=_TOKEN,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
            elapsed_seconds=13,
        )
    else:
        state = _passed()
    corrupted = copy.copy(state)
    assert state.capability is not None
    capability = copy.copy(state.capability)
    if mutation == "token":
        object.__setattr__(
            capability,
            "token_hash",
            hashlib.sha256(("f" * 64).encode("ascii")).hexdigest(),
        )
    elif mutation == "window":
        object.__setattr__(capability, "issued_at", 2_000)
        object.__setattr__(capability, "expires_at", 2_900)
    else:
        object.__setattr__(capability, "consumed", False)
        object.__setattr__(capability, "consumed_by", None)
        object.__setattr__(capability, "consumer_binding_hash", None)
        object.__setattr__(capability, "consumed_at", None)
    object.__setattr__(corrupted, "capability", capability)

    with pytest.raises(SchedulerPreflightError, match="does not bind"):
        preflight_result(corrupted)


def test_only_sacct_completed_zero_exit_reaches_evidence_gate() -> None:
    cases = (
        (_queue(_polling(), "COMPLETED"), None, "polling"),
        (None, _accounting(_polling(), "COMPLETED", (1, 0)), "indeterminate"),
        (None, _accounting(_polling(), "COMPLETED", None), "polling"),
        (None, _accounting(_polling(), "FAILED", (1, 0)), "failed"),
        (None, _accounting(_polling(), "REQUEUED", None), "indeterminate"),
    )
    for queue, accounting, expected in cases:
        state = _polling()
        if queue is not None:
            queue = SlurmObservation(source="squeue", job=_job(state), state=queue.state)
        if accounting is not None:
            accounting = SlurmObservation(
                source="sacct",
                job=_job(state),
                state=accounting.state,
                exit_code=accounting.exit_code,
            )
        result = record_scheduler_poll(
            state,
            queue=queue,
            accounting=accounting,
            elapsed_seconds=10,
        )
        assert result.phase == expected
        assert preflight_result(result)["preflight_token"] is None

    succeeded = _polling()
    succeeded = record_scheduler_poll(
        succeeded,
        queue=None,
        accounting=_accounting(succeeded, "COMPLETED", (0, 0)),
        elapsed_seconds=10,
    )
    assert succeeded.phase == "awaiting_evidence"


def test_missing_observations_poll_until_exact_timeout_without_token() -> None:
    state = _polling()
    state = record_scheduler_poll(
        state,
        queue=None,
        accounting=None,
        elapsed_seconds=59,
    )
    assert state.phase == "polling"
    assert state.reason_code == "SLURM_OBSERVATION_MISSING"

    state = record_scheduler_poll(
        state,
        queue=None,
        accounting=None,
        elapsed_seconds=60,
    )
    assert state.phase == "timed_out"
    assert preflight_result(state)["preflight_token"] is None
    with pytest.raises(SchedulerPreflightError):
        issue_capability(
            state,
            token_hash=_TOKEN_HASH,
            elapsed_seconds=60,
        )


def test_pending_timeout_starts_at_release_intent_not_submit_intent() -> None:
    prepared = _prepared()
    held = record_held_submission(prepared, _held_job(prepared))
    release_ready = record_release_intent(held, elapsed_seconds=59)
    state = record_held_release(release_ready)

    state = record_scheduler_poll(
        state,
        queue=_queue(state, "PENDING"),
        accounting=None,
        elapsed_seconds=60,
    )
    assert state.phase == "polling"
    assert state.pending_since_seconds == 59

    state = record_scheduler_poll(
        state,
        queue=_queue(state, "PENDING"),
        accounting=None,
        elapsed_seconds=119,
    )
    assert state.phase == "timed_out"
    assert state.reason_code == "SLURM_PREFLIGHT_TIMEOUT"


def test_pending_timeout_does_not_apply_after_running_was_observed() -> None:
    state = _polling()
    state = record_scheduler_poll(
        state,
        queue=_queue(state, "RUNNING"),
        accounting=None,
        elapsed_seconds=59,
    )
    assert state.started is True

    state = record_scheduler_poll(
        state,
        queue=_queue(state, "RUNNING"),
        accounting=None,
        elapsed_seconds=600,
    )
    assert state.phase == "polling"
    assert state.started is True
    assert state.reason_code == "SLURM_RUNNING"

    missing_after_start = record_scheduler_poll(
        state,
        queue=None,
        accounting=None,
        elapsed_seconds=601,
    )
    assert missing_after_start.phase == "polling"
    assert missing_after_start.started is True
    assert missing_after_start.reason_code == "SLURM_OBSERVATION_MISSING"


def test_overall_deadline_blocks_late_scheduler_evidence_and_capability() -> None:
    late_poll = record_scheduler_poll(
        _polling(),
        queue=None,
        accounting=None,
        elapsed_seconds=1_030,
    )
    assert late_poll.phase == "timed_out"
    assert late_poll.reason_code == "SLURM_PREFLIGHT_OVERALL_TIMEOUT"

    awaiting = _awaiting_evidence()
    late_evidence = record_compute_evidence(
        awaiting,
        _evidence_mapping(awaiting),
        elapsed_seconds=1_030,
    )
    assert late_evidence.phase == "timed_out"
    assert preflight_result(late_evidence)["preflight_token"] is None

    late_issue = issue_capability(
        _candidate(),
        token_hash=_TOKEN_HASH,
        elapsed_seconds=1_030,
    )
    assert late_issue.phase == "timed_out"
    assert preflight_result(late_issue)["preflight_token"] is None

    submit_unknown = record_submit_unknown(_prepared())
    discovered = record_held_submission(submit_unknown, _held_job(submit_unknown))
    late_release = record_release_intent(discovered, elapsed_seconds=1_030)
    assert late_release.phase == "timed_out"
    with pytest.raises(SchedulerPreflightError):
        record_held_release(late_release)


def test_driver_timeout_returns_same_state_before_any_deadline() -> None:
    submit_unknown = record_submit_unknown(_prepared())
    held = record_held_submission(submit_unknown, _held_job(submit_unknown))
    release_unknown = record_release_unknown(record_release_intent(held, elapsed_seconds=1))
    polling = _polling()
    awaiting = _awaiting_evidence()
    candidate = _candidate()

    assert record_driver_timeout(submit_unknown, elapsed_seconds=1_029) is submit_unknown
    assert record_driver_timeout(held, elapsed_seconds=1_029) is held
    assert record_driver_timeout(release_unknown, elapsed_seconds=60) is release_unknown
    assert record_driver_timeout(polling, elapsed_seconds=59) is polling
    assert record_driver_timeout(awaiting, elapsed_seconds=1_029) is awaiting
    assert record_driver_timeout(candidate, elapsed_seconds=1_029) is candidate


@pytest.mark.parametrize(
    "state",
    [
        pytest.param(record_submit_unknown(_prepared()), id="submit-unknown"),
        pytest.param(
            record_held_submission(
                record_submit_unknown(_prepared()),
                _held_job(record_submit_unknown(_prepared())),
            ),
            id="held",
        ),
        pytest.param(
            record_release_unknown(
                record_release_intent(
                    record_held_submission(_prepared(), _held_job(_prepared())),
                    elapsed_seconds=1,
                )
            ),
            id="release-unknown",
        ),
        pytest.param(_polling(), id="polling"),
        pytest.param(_awaiting_evidence(), id="awaiting-evidence"),
        pytest.param(_candidate(), id="candidate"),
    ],
)
def test_driver_timeout_applies_exact_overall_boundary(
    state: SchedulerPreflightState,
) -> None:
    timed_out = record_driver_timeout(state, elapsed_seconds=1_030)

    assert timed_out.phase == "timed_out"
    assert timed_out.reason_code == "SLURM_PREFLIGHT_OVERALL_TIMEOUT"
    assert timed_out.elapsed_seconds == 1_030
    assert timed_out.job == state.job
    assert timed_out.evidence == state.evidence
    assert timed_out.evidence_sha256 == state.evidence_sha256


def test_driver_timeout_applies_pending_boundary_only_before_started() -> None:
    polling = _polling()
    before = record_driver_timeout(polling, elapsed_seconds=59)
    assert before is polling

    timed_out = record_driver_timeout(polling, elapsed_seconds=60)
    assert timed_out.phase == "timed_out"
    assert timed_out.reason_code == "SLURM_PREFLIGHT_TIMEOUT"
    assert timed_out.elapsed_seconds == 60

    release_ready = record_release_intent(
        record_held_submission(_prepared(), _held_job(_prepared())),
        elapsed_seconds=7,
    )
    release_unknown = record_release_unknown(release_ready)
    assert record_driver_timeout(release_unknown, elapsed_seconds=66) is release_unknown
    release_timed_out = record_driver_timeout(release_unknown, elapsed_seconds=67)
    assert release_timed_out.phase == "timed_out"
    assert release_timed_out.reason_code == "SLURM_PREFLIGHT_TIMEOUT"

    started = record_scheduler_poll(
        polling,
        queue=_queue(polling, "RUNNING"),
        accounting=None,
        elapsed_seconds=10,
    )
    assert started.started is True
    assert record_driver_timeout(started, elapsed_seconds=60) is started


def test_driver_timeout_rejects_elapsed_regression() -> None:
    candidate = _candidate()

    with pytest.raises(SchedulerPreflightError, match="must be monotonic"):
        record_driver_timeout(candidate, elapsed_seconds=candidate.elapsed_seconds - 1)


@pytest.mark.parametrize(
    "state",
    [
        pytest.param(_prepared(), id="prepared"),
        pytest.param(
            record_release_intent(
                record_held_submission(_prepared(), _held_job(_prepared())),
                elapsed_seconds=1,
            ),
            id="release-ready",
        ),
        pytest.param(_passed(), id="passed"),
        pytest.param(
            record_driver_timeout(_candidate(), elapsed_seconds=1_030),
            id="timed-out",
        ),
        pytest.param(
            record_clock_discontinuity(_candidate()),
            id="indeterminate",
        ),
        pytest.param(
            record_compute_evidence(
                _awaiting_evidence(),
                _evidence_mapping(_awaiting_evidence(), failed="input_paths"),
                elapsed_seconds=11,
            ),
            id="failed",
        ),
    ],
)
def test_driver_transitions_reject_phases_outside_durable_recovery(
    state: SchedulerPreflightState,
) -> None:
    if state.phase == "passed":
        timed_out = record_driver_timeout(
            state,
            elapsed_seconds=max(1_030, state.elapsed_seconds),
        )
        assert timed_out.phase == "timed_out"
        assert timed_out.capability == state.capability
    else:
        with pytest.raises(SchedulerPreflightError, match="current phase"):
            record_driver_timeout(state, elapsed_seconds=max(1_030, state.elapsed_seconds))
    if state.phase == "passed":
        invalidated = record_clock_discontinuity(state)
        assert invalidated.phase == "indeterminate"
        assert invalidated.capability == state.capability
    else:
        with pytest.raises(SchedulerPreflightError, match="current phase"):
            record_clock_discontinuity(state)


@pytest.mark.parametrize(
    "state",
    [
        pytest.param(record_submit_unknown(_prepared()), id="submit-unknown"),
        pytest.param(
            record_held_submission(_prepared(), _held_job(_prepared())),
            id="held",
        ),
        pytest.param(
            record_release_unknown(
                record_release_intent(
                    record_held_submission(_prepared(), _held_job(_prepared())),
                    elapsed_seconds=1,
                )
            ),
            id="release-unknown",
        ),
        pytest.param(_polling(), id="polling"),
        pytest.param(_awaiting_evidence(), id="awaiting-evidence"),
        pytest.param(_candidate(), id="candidate"),
    ],
)
def test_clock_discontinuity_preserves_bound_attempt_evidence(
    state: SchedulerPreflightState,
) -> None:
    result = record_clock_discontinuity(state)

    assert result.phase == "indeterminate"
    assert result.reason_code == "SCHEDULER_CLOCK_DISCONTINUITY"
    assert result.elapsed_seconds == state.elapsed_seconds
    assert result.job == state.job
    assert result.held_job == state.held_job
    assert result.terminal_observation == state.terminal_observation
    assert result.evidence == state.evidence
    assert result.evidence_sha256 == state.evidence_sha256


def test_ambiguous_submit_and_release_recover_only_from_positive_evidence() -> None:
    submit_unknown = record_submit_unknown(_prepared())
    assert submit_unknown.phase == "submit_unknown"
    assert submit_unknown.job is None

    prepared = _prepared()
    held = record_held_submission(prepared, _held_job(prepared))
    release_ready = record_release_intent(held, elapsed_seconds=1)
    release_unknown = record_release_unknown(release_ready)
    assert release_unknown.phase == "release_unknown"
    assert release_unknown.job == held.job

    for unknown in (submit_unknown, release_unknown):
        assert preflight_result(unknown)["preflight_token"] is None
        with pytest.raises(SchedulerPreflightError):
            issue_capability(
                unknown,
                token_hash=_TOKEN_HASH,
                elapsed_seconds=1,
            )

    recovered_submit = record_held_submission(submit_unknown, _held_job(submit_unknown))
    assert recovered_submit.phase == "held"
    with pytest.raises(SchedulerPreflightError):
        record_held_submission(release_unknown, _held_job(release_unknown))


def test_release_unknown_requires_positive_exact_scheduler_progress() -> None:
    prepared = _prepared()
    held = record_held_submission(prepared, _held_job(prepared))
    release_ready = record_release_intent(held, elapsed_seconds=1)
    unknown = record_release_unknown(release_ready)

    missing = record_scheduler_poll(
        unknown,
        queue=None,
        accounting=None,
        elapsed_seconds=1,
    )
    assert missing.phase == "release_unknown"
    pending = record_scheduler_poll(
        missing,
        queue=_queue(missing, "PENDING"),
        accounting=None,
        elapsed_seconds=2,
    )
    assert pending.phase == "release_unknown"
    active = record_scheduler_poll(
        pending,
        queue=_queue(pending, "RUNNING"),
        accounting=None,
        elapsed_seconds=3,
    )
    assert active.phase == "polling"

    terminal_unknown = record_release_unknown(release_ready)
    completed = record_scheduler_poll(
        terminal_unknown,
        queue=None,
        accounting=_accounting(terminal_unknown, "COMPLETED", (0, 0)),
        elapsed_seconds=3,
    )
    assert completed.phase == "awaiting_evidence"


def test_recovered_release_intent_becomes_unknown_without_replaying_release() -> None:
    prepared = _prepared()
    held = record_held_submission(prepared, _held_job(prepared))
    persisted_intent = record_release_intent(held, elapsed_seconds=1)

    recovered = record_release_unknown(persisted_intent)
    assert recovered.phase == "release_unknown"
    with pytest.raises(SchedulerPreflightError):
        record_held_release(recovered)
    still_unknown = record_scheduler_poll(
        recovered,
        queue=None,
        accounting=None,
        elapsed_seconds=2,
    )
    assert still_unknown.phase == "release_unknown"


def test_indeterminate_conflict_and_restart_never_mint_token() -> None:
    state = _polling()
    conflict = record_scheduler_poll(
        state,
        queue=_queue(state, "RUNNING"),
        accounting=_accounting(state, "COMPLETED", (0, 0)),
        elapsed_seconds=10,
    )
    assert conflict.phase == "indeterminate"

    state = _polling()
    restart = record_scheduler_poll(
        state,
        queue=_queue(state, "REQUEUED"),
        accounting=None,
        elapsed_seconds=10,
    )
    assert restart.phase == "indeterminate"
    for terminal in (conflict, restart):
        assert preflight_result(terminal)["preflight_token"] is None
        with pytest.raises(SchedulerPreflightError):
            issue_capability(
                terminal,
                token_hash=_TOKEN_HASH,
                elapsed_seconds=11,
            )


def test_terminal_like_observation_cannot_regress_to_active_then_pass() -> None:
    state = _polling()
    state = record_scheduler_poll(
        state,
        queue=_queue(state, "FAILED"),
        accounting=None,
        elapsed_seconds=5,
    )
    assert state.phase == "polling"
    assert state.terminal_seen is True

    regressed = record_scheduler_poll(
        state,
        queue=_queue(state, "RUNNING"),
        accounting=None,
        elapsed_seconds=6,
    )
    assert regressed.phase == "indeterminate"
    assert regressed.reason_code == "SLURM_TERMINAL_STATE_REGRESSION"
    with pytest.raises(SchedulerPreflightError):
        issue_capability(
            regressed,
            token_hash=_TOKEN_HASH,
            elapsed_seconds=7,
        )


def test_terminal_like_state_must_match_final_accounting_state() -> None:
    state = _polling()
    state = record_scheduler_poll(
        state,
        queue=_queue(state, "FAILED"),
        accounting=None,
        elapsed_seconds=5,
    )
    conflict = record_scheduler_poll(
        state,
        queue=None,
        accounting=_accounting(state, "COMPLETED", (0, 0)),
        elapsed_seconds=6,
    )
    assert conflict.phase == "indeterminate"
    assert conflict.reason_code == "SLURM_OBSERVATION_CONFLICT"

    consistent = _polling()
    consistent = record_scheduler_poll(
        consistent,
        queue=_queue(consistent, "COMPLETED"),
        accounting=None,
        elapsed_seconds=5,
    )
    consistent = record_scheduler_poll(
        consistent,
        queue=None,
        accounting=_accounting(consistent, "COMPLETED", (0, 0)),
        elapsed_seconds=6,
    )
    assert consistent.phase == "awaiting_evidence"


@pytest.mark.parametrize(
    ("raw_state", "exit_code", "code"),
    [
        ("COMPLETED", (1, 0), "SLURM_SUCCESS_EXIT_CONFLICT"),
        ("FAILED", (0, 0), "SLURM_FAILURE_EXIT_CONFLICT"),
    ],
)
def test_terminal_exit_conflict_retains_exact_operator_evidence(
    raw_state: str,
    exit_code: tuple[int, int],
    code: str,
) -> None:
    state = _polling()
    observation = _accounting(state, raw_state, exit_code)
    result = record_scheduler_poll(
        state,
        queue=None,
        accounting=observation,
        elapsed_seconds=5,
    )

    assert result.phase == "indeterminate"
    assert result.reason_code == code
    assert result.terminal_seen is True
    assert result.terminal_observation == observation


def test_scheduler_observation_must_bind_exact_job_marker_and_submit_time() -> None:
    state = _polling()
    other = SlurmObservation(
        source="squeue",
        job=SlurmJobRef(
            job_id=_JOB_ID,
            submission_marker=state.submission_marker,
            submitted_at="2026-07-19T12:34:57",
        ),
        state="RUNNING",
    )
    with pytest.raises(SchedulerPreflightError, match="another job attempt"):
        record_scheduler_poll(
            state,
            queue=other,
            accounting=None,
            elapsed_seconds=5,
        )


def test_poll_clock_is_strict_monotonic_and_phase_transitions_are_closed() -> None:
    state = _polling()
    state = record_scheduler_poll(
        state,
        queue=_queue(state, "RUNNING"),
        accounting=None,
        elapsed_seconds=10,
    )
    with pytest.raises(SchedulerPreflightError, match="monotonic"):
        record_scheduler_poll(
            state,
            queue=_queue(state, "RUNNING"),
            accounting=None,
            elapsed_seconds=9,
        )
    with pytest.raises(SchedulerPreflightError):
        record_held_release(state)
    with pytest.raises(SchedulerPreflightError):
        record_compute_evidence(state, {}, elapsed_seconds=11)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("preflight_id", "preflight-2"),
        ("profile_hash", "f" * 64),
        ("scheduler_policy_hash", "f" * 64),
        ("project_hash", "f" * 64),
        ("input_set_hash", "f" * 64),
        ("manifest_sha256", "f" * 64),
        ("worker_sha256", "f" * 64),
        ("job_id", "54321"),
        ("submission_marker", "f" * 64),
    ],
)
def test_compute_evidence_must_bind_every_manifest_worker_and_job_identity(
    field: str,
    replacement: str,
) -> None:
    state = _awaiting_evidence()
    value = _evidence_mapping(state)
    value[field] = replacement

    with pytest.raises(SchedulerPreflightError, match="exact preflight attempt"):
        record_compute_evidence(state, value, elapsed_seconds=11)


def test_failed_compute_check_is_retained_but_never_becomes_candidate() -> None:
    state = _awaiting_evidence()
    failed = record_compute_evidence(
        state,
        _evidence_mapping(state, failed="input_paths"),
        elapsed_seconds=11,
    )

    assert failed.phase == "failed"
    assert failed.reason_code == "PATH_UNAVAILABLE"
    assert failed.evidence is not None
    assert failed.evidence_sha256 is not None
    assert preflight_result(failed)["preflight_token"] is None
    with pytest.raises(SchedulerPreflightError):
        issue_capability(
            failed,
            token_hash=_TOKEN_HASH,
            elapsed_seconds=12,
        )


@pytest.mark.parametrize(
    ("token", "elapsed_seconds", "message"),
    [
        ("f" * 64, 13, "invalid"),
        (_TOKEN, 912, "expired"),
        ("0" * 64, 13, "trusted token"),
    ],
)
def test_capability_consumption_rejects_wrong_expired_and_placeholder_tokens(
    token: str,
    elapsed_seconds: int,
    message: str,
) -> None:
    with pytest.raises(SchedulerPreflightError, match=message):
        consume_capability(
            _passed(),
            token=token,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
            elapsed_seconds=elapsed_seconds,
        )


def test_capability_state_accepts_only_hash_and_never_exposes_raw_token() -> None:
    parameters = inspect.signature(issue_capability).parameters
    assert "token_hash" in parameters and "trusted_token" not in parameters
    for state in (_prepared(), _polling(), _awaiting_evidence()):
        assert preflight_result(state)["preflight_token"] is None
        with pytest.raises(SchedulerPreflightError):
            issue_capability(
                state,
                token_hash=_TOKEN_HASH,
                elapsed_seconds=12,
            )

    with pytest.raises(SchedulerPreflightError):
        issue_capability(
            _candidate(),
            token_hash="0" * 64,
            elapsed_seconds=12,
        )


def test_scheduler_preflight_source_has_no_external_operation_surface() -> None:
    source_path = Path(__file__).parents[1] / "src" / "bioexec" / "scheduler_preflight.py"
    syntax = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    forbidden_imports = {
        "asyncio",
        "http",
        "os",
        "secrets",
        "shlex",
        "socket",
        "subprocess",
        "tempfile",
        "time",
        "urllib",
    }
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] not in forbidden_imports for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            assert (node.module or "").split(".")[0] not in forbidden_imports
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"open", "exec", "eval", "compile", "__import__"}


@pytest.mark.parametrize(
    "path",
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
def test_version_one_production_paths_do_not_import_scheduler_preflight(path: str) -> None:
    source_path = Path(__file__).parents[2] / path
    syntax = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all(not alias.name.endswith("scheduler_preflight") for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or not node.module.endswith("scheduler_preflight")


def test_version_one_remote_import_graph_does_not_load_scheduler_preflight() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = """
import importlib
import sys
for name in (
    "bioexec.main",
    "bioexec.protocol",
    "bioexec.config",
    "bioexec.preflight",
    "bioexec.deployment",
    "bioexec.runner",
):
    importlib.import_module(name)
raise SystemExit(7 if "bioexec.scheduler_preflight" in sys.modules else 0)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).parents[2],
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(source_root),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr


def test_pure_contract_does_not_touch_host_process_network_clock_or_rng(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("dormant scheduler preflight performed an external operation")

    patches: tuple[tuple[object, str], ...] = (
        (os, "getenv"),
        (os, "system"),
        (socket, "socket"),
        (subprocess, "run"),
        (subprocess, "Popen"),
        (time, "sleep"),
        (time, "time"),
        (secrets, "token_hex"),
        (secrets, "token_bytes"),
    )
    for owner, name in patches:
        monkeypatch.setattr(owner, name, forbidden)

    state = _prepared()
    state = record_held_submission(state, _held_job(state))
    state = record_release_intent(state, elapsed_seconds=1)
    state = record_held_release(state)
    state = record_scheduler_poll(
        state,
        queue=None,
        accounting=_accounting(state, "COMPLETED", (0, 0)),
        elapsed_seconds=10,
    )
    state = record_compute_evidence(state, _evidence_mapping(state), elapsed_seconds=11)
    state = issue_capability(
        state,
        token_hash=_TOKEN_HASH,
        elapsed_seconds=12,
    )
    assert preflight_result(state)["status"] == "passed"


def test_public_api_does_not_offer_generic_command_script_or_argv_inputs() -> None:
    functions: tuple[Callable[..., object], ...] = (
        parse_compute_manifest,
        prepare_preflight,
        record_held_submission,
        record_release_intent,
        record_held_release,
        record_submit_unknown,
        record_release_unknown,
        record_clock_discontinuity,
        record_driver_timeout,
        record_scheduler_poll,
        record_compute_evidence,
        issue_capability,
    )
    forbidden = {"command", "shell", "script", "script_bytes", "script_path", "argv", "flags"}
    for function in functions:
        assert forbidden.isdisjoint(inspect.signature(function).parameters)


def test_module_contract_constants_and_twelve_check_names_are_frozen() -> None:
    assert scheduler_preflight_module.MANIFEST_VERSION == "1.1"
    assert scheduler_preflight_module.EVIDENCE_VERSION == "1.0"
    assert scheduler_preflight_module.WORKER_CONTRACT_VERSION == "1.0"
    assert tuple(sorted(COMPUTE_CHECK_NAMES)) == COMPUTE_CHECK_NAMES
    assert len(COMPUTE_CHECK_NAMES) == len(set(COMPUTE_CHECK_NAMES)) == 12
