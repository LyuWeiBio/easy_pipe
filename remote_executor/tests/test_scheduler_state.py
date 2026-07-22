"""Durability and recovery tests for the dormant M7 scheduler state store."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_state as state_module
from bioexec.scheduler_bindings import SchedulerBindingError, expected_worker_paths
from bioexec.scheduler_clock import ClockSample
from bioexec.scheduler_config_loader import (
    TrustedSchedulerConfig,
    load_trusted_scheduler_config,
)
from bioexec.scheduler_preflight import (
    COMPUTE_CHECK_NAMES,
    SchedulerPreflightState,
    canonical_evidence_bytes,
    canonical_manifest_bytes,
    input_set_hash,
    parse_compute_evidence,
    parse_compute_manifest,
    preflight_overall_timeout_seconds,
    preflight_result,
    prepare_preflight,
)
from bioexec.scheduler_state import (
    SchedulerCapabilityExpiredError,
    SchedulerCapabilityUnavailableError,
    SchedulerClockDiscontinuityError,
    SchedulerMutationPermit,
    SchedulerMutationPermitError,
    SchedulerPreflightStore,
    SchedulerStateBusyError,
    SchedulerStateCommitUnknown,
    SchedulerStateConflictError,
    SchedulerStateContractError,
    SchedulerStateDeadlineError,
    SchedulerStateInvalidError,
    SchedulerStatePreconditionError,
    SchedulerStateSnapshot,
    SchedulerWorkerEvidencePending,
)
from bioexec.slurm import SlurmHeldJob, SlurmJobRef, SlurmObservation

_REQUEST_SHA256 = "9" * 64
_PROFILE_HASH = "a" * 64
_SUBMITTED_AT = "2026-07-19T12:34:56"
_JOB_ID = "12345"
_NAMESPACE = "scheduler-preflights-v1"
_RAW_CAPABILITY = "0123456789abcdef" * 4
_CONSUMER_BINDING_HASH = "d" * 64


class _AdvancingClock:
    """Deterministic sleep-inclusive clock shared by restarted test stores."""

    def __init__(self) -> None:
        self.epoch_id = "test-boot"
        self.boottime_ns = 1_000_000_000
        self.step_ns = 1_000_000_000
        self._lock = threading.Lock()

    def sample(self) -> ClockSample:
        with self._lock:
            sample = ClockSample(
                epoch_id=self.epoch_id,
                boottime_ns=self.boottime_ns,
            )
            self.boottime_ns += self.step_ns
        return sample


@dataclass(frozen=True)
class StateFixture:
    config: TrustedSchedulerConfig
    config_path: Path
    prepared: SchedulerPreflightState
    state_root: Path
    clock: _AdvancingClock

    @property
    def attempt(self) -> Path:
        return self.state_root / _NAMESPACE / self.prepared.manifest.preflight_id


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


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


def _write_executable(path: Path) -> None:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    path.chmod(0o755)


@pytest.fixture
def state_fixture(tmp_path: Path) -> StateFixture:
    roots: dict[str, Path] = {}
    for role in ("read", "deploy", "work", "output", "cache", "state"):
        root = tmp_path / role
        root.mkdir(mode=0o700)
        roots[role] = root

    executable_roles = (
        "python",
        "java",
        "nextflow",
        "apptainer",
        "compute_worker",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o700)
    executable_leaves = {
        role: (
            "python3"
            if role == "python"
            else "bioexec-compute-preflight"
            if role == "compute_worker"
            else role
        )
        for role in executable_roles
    }
    executables = {role: bin_dir / executable_leaves[role] for role in executable_roles}
    for executable in executables.values():
        _write_executable(executable)

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    nextflow_jar = runtime_dir / "nextflow-24.10.0-one.jar"
    nextflow_jar.write_bytes(b"synthetic pinned Nextflow jar\n")
    nextflow_jar.chmod(0o444)

    policy: dict[str, Any] = {
        "partition": "compute",
        "account": "bioinfo",
        "qos": "normal",
        "time_limit": "00:15:00",
        "cpus_per_task": 8,
        "memory_mib": 16_384,
        "submit_timeout_seconds": 1,
        "status_poll_seconds": 5,
        "max_pending_seconds": 60,
    }
    config_value: dict[str, Any] = {
        "schema_version": "2.0",
        "profile_version": "2.0",
        "profile_id": "hpc01-slurm",
        "profile_hash": _PROFILE_HASH,
        "runtime": {
            "launch_backend": "slurm",
            "workflow_engine": "nextflow",
            "workflow_executor": "local",
            "container_engine": "apptainer",
            "topology": "single_allocation_nextflow_local",
        },
        "scheduler": policy,
        "read_roots": [str(roots["read"])],
        "deploy_roots": [str(roots["deploy"])],
        "work_roots": [str(roots["work"])],
        "output_roots": [str(roots["output"])],
        "cache_roots": [str(roots["cache"])],
        "state_root": str(roots["state"]),
        "executables": {role: str(path) for role, path in executables.items()},
        "nextflow_version": "24.10.0",
        "nextflow_jar": str(nextflow_jar),
        "nextflow_jar_sha256": hashlib.sha256(nextflow_jar.read_bytes()).hexdigest(),
        "approval_key_id": "controller-2026-01",
        "approval_hmac_key": "c" * 64,
        "limits": {
            "max_command_output_bytes": 1024,
            "command_timeout_seconds": 1.0,
        },
    }
    config_path = tmp_path / "scheduler-config.json"
    config_path.write_text(
        json.dumps(
            config_value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    config_path.chmod(0o600)
    config = load_trusted_scheduler_config(config_path)

    worker_dir = roots["state"] / "scheduler-preflights-v1" / "preflight-1"
    execution_paths = (str(roots["read"] / "sample_R1.fastq.gz"),)
    manifest_value: dict[str, Any] = {
        "manifest_version": "1.1",
        "preflight_id": "preflight-1",
        "profile_version": "2.0",
        "profile_id": config.contract.profile_id,
        "profile_hash": config.contract.profile_hash,
        "scheduler_policy_hash": config.scheduler_policy_hash,
        "scheduler_policy": policy,
        "compute_runtime": {
            "python_executable": str(executables["python"]),
            "python_sha256": config.executables["python"].sha256,
            "java_executable": str(executables["java"]),
            "java_sha256": config.executables["java"].sha256,
            "nextflow_executable": str(executables["nextflow"]),
            "nextflow_sha256": config.executables["nextflow"].sha256,
            "nextflow_version": config.contract.nextflow_version,
            "nextflow_jar": str(nextflow_jar),
            "nextflow_jar_sha256": config.nextflow_jar.sha256,
            "apptainer_executable": str(executables["apptainer"]),
            "apptainer_sha256": config.executables["apptainer"].sha256,
            "command_timeout_seconds": config.contract.limits.command_timeout_seconds,
            "max_command_output_bytes": config.contract.limits.max_command_output_bytes,
        },
        "project_hash": _project_hash(),
        "artifact_hashes": _artifact_hashes(),
        "source_host": "source-host",
        "execution_host": "compute-host",
        "host_relation": "shared",
        "source_paths": [str(roots["read"] / "sample_R1.fastq.gz")],
        "execution_paths": list(execution_paths),
        "path_mapping": [
            {
                "source_prefix": str(roots["read"]),
                "execution_prefix": str(roots["read"]),
            }
        ],
        "input_set_hash": input_set_hash(execution_paths),
        "deploy_dir": str(roots["deploy"] / "project-1"),
        "work_dir": str(roots["work"] / "run-1"),
        "output_dir": str(roots["output"] / "run-1"),
        "cache_dir": str(roots["cache"] / "job-1"),
        "containers": [
            {
                "name": "fastqc",
                "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
                "digest": f"sha256:{'5' * 64}",
                "local_path": str(roots["cache"] / "fastqc.sif"),
                "file_sha256": "6" * 64,
            },
            {
                "name": "multiqc",
                "image": "quay.io/biocontainers/multiqc:1.27.1--pyhdfd78af_0",
                "digest": f"sha256:{'7' * 64}",
                "local_path": str(roots["cache"] / "multiqc.sif"),
                "file_sha256": "8" * 64,
            },
        ],
        "minimum_free_bytes": config.contract.limits.minimum_free_bytes,
        "network_disabled": True,
        "resume_run_id": None,
        "resume_directory_identities": None,
        "preflight_ttl_seconds": config.contract.limits.preflight_ttl_seconds,
        "worker": {
            "contract_version": "1.0",
            "executable": str(executables["compute_worker"]),
            "executable_sha256": config.executables["compute_worker"].sha256,
            "manifest_path": str(worker_dir / "manifest.json"),
            "evidence_path": str(worker_dir / "evidence.json"),
        },
    }
    prepared = prepare_preflight(parse_compute_manifest(manifest_value))
    return StateFixture(
        config=config,
        config_path=config_path,
        prepared=prepared,
        state_root=roots["state"],
        clock=_AdvancingClock(),
    )


def _new_store(fixture: StateFixture) -> SchedulerPreflightStore:
    return SchedulerPreflightStore(fixture.config, clock=fixture.clock)


def _create(fixture: StateFixture, store: SchedulerPreflightStore) -> SchedulerStateSnapshot:
    return store.create_or_load(fixture.prepared, request_sha256=_REQUEST_SHA256)


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


def _wrong_marker_held_job() -> SlurmHeldJob:
    return SlurmHeldJob(
        job=SlurmJobRef(
            job_id=_JOB_ID,
            submission_marker="f" * 64,
            submitted_at=_SUBMITTED_AT,
        ),
        state="PENDING",
        reason="JobHeldUser",
    )


def _consume(
    permit: SchedulerMutationPermit,
    operation: state_module.SchedulerMutationOperation,
    store: SchedulerPreflightStore,
) -> float:
    return state_module._consume_mutation_permit(
        permit,
        operation,
        permit.state,
        store.config,
    )


def _held_snapshot(
    fixture: StateFixture,
    store: SchedulerPreflightStore,
) -> SchedulerStateSnapshot:
    initial = _create(fixture, store)
    with store.claim_submit(initial) as permit:
        _consume(permit, "submit_held", store)
        return store.record_held(
            permit,
            _held_job(permit.state),
            invocation_sha256="e" * 64,
        )


def _awaiting_evidence_snapshot(
    fixture: StateFixture,
    store: SchedulerPreflightStore,
) -> SchedulerStateSnapshot:
    held = _held_snapshot(fixture, store)
    with store.claim_release(held, elapsed_seconds=1):
        pass
    unknown = store.load(
        fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert unknown.state.job is not None
    active = store.record_scheduler_poll(
        unknown,
        queue=SlurmObservation(source="squeue", job=unknown.state.job, state="RUNNING"),
        accounting=None,
        elapsed_seconds=2,
    )
    return store.record_scheduler_poll(
        active,
        queue=None,
        accounting=SlurmObservation(
            source="sacct",
            job=active.state.job,
            state="COMPLETED",
            exit_code=(0, 0),
        ),
        elapsed_seconds=3,
    )


def _worker_evidence_value(state: SchedulerPreflightState) -> dict[str, Any]:
    assert state.job is not None
    return {
        "evidence_version": "1.0",
        "preflight_id": state.manifest.preflight_id,
        "profile_id": state.manifest.profile_id,
        "profile_hash": state.manifest.profile_hash,
        "scheduler_policy_hash": state.manifest.scheduler_policy_hash,
        "project_hash": state.manifest.project_hash,
        "input_set_hash": state.manifest.input_set_hash,
        "manifest_sha256": state.manifest_sha256,
        "worker_sha256": state.manifest.worker.executable_sha256,
        "job_id": state.job.job_id,
        "submission_marker": state.job.submission_marker,
        "status": "passed",
        "checks": [
            {
                "name": name,
                "status": "passed",
                "code": "OK",
                "evidence_sha256": hashlib.sha256(name.encode("ascii")).hexdigest(),
            }
            for name in COMPUTE_CHECK_NAMES
        ],
    }


def _candidate_snapshot(
    fixture: StateFixture,
    store: SchedulerPreflightStore,
) -> SchedulerStateSnapshot:
    awaiting = _awaiting_evidence_snapshot(fixture, store)
    evidence_path = fixture.attempt / "evidence.json"
    evidence_path.write_bytes(
        canonical_evidence_bytes(parse_compute_evidence(_worker_evidence_value(awaiting.state)))
    )
    evidence_path.chmod(0o600)
    return store.ingest_worker_evidence(awaiting, elapsed_seconds=4)


def _write_canonical(path: Path, value: dict[str, Any]) -> None:
    path.write_bytes(
        (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    )
    path.chmod(0o600)


def test_create_or_load_is_idempotent_only_for_the_exact_request(
    state_fixture: StateFixture,
) -> None:
    first_store = _new_store(state_fixture)
    first = _create(state_fixture, first_store)
    repeated = _create(state_fixture, first_store)
    restarted = _new_store(state_fixture).create_or_load(
        state_fixture.prepared,
        request_sha256=_REQUEST_SHA256,
    )

    assert first.state == repeated.state == restarted.state == state_fixture.prepared
    assert first.revision == repeated.revision == restarted.revision == 0
    assert first.journal_sha256 == repeated.journal_sha256 == restarted.journal_sha256
    assert first.submit_intent_sha256 is None
    assert first.release_intent_sha256 is None
    assert (state_fixture.attempt / "manifest.json").read_bytes() == canonical_manifest_bytes(
        state_fixture.prepared.manifest
    )

    with pytest.raises(SchedulerStateConflictError) as changed:
        first_store.create_or_load(
            state_fixture.prepared,
            request_sha256="8" * 64,
        )
    assert changed.value.reason_code == "SCHEDULER_REQUEST_HASH_CONFLICT"

    with pytest.raises(SchedulerStateConflictError) as changed_load:
        first_store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256="8" * 64,
        )
    assert changed_load.value.reason_code == "SCHEDULER_REQUEST_HASH_CONFLICT"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("preflight_ttl_seconds", 901),
        ("minimum_free_bytes", 1024 * 1024),
    ],
)
def test_prepared_manifest_limits_must_bind_trusted_config_before_attempt_creation(
    state_fixture: StateFixture,
    field: str,
    value: int,
) -> None:
    manifest = state_fixture.prepared.manifest.as_mapping()
    manifest[field] = value
    mismatched = prepare_preflight(parse_compute_manifest(manifest))

    with pytest.raises(SchedulerStateContractError, match="trusted compute installation"):
        _new_store(state_fixture).create_or_load(
            mismatched,
            request_sha256=_REQUEST_SHA256,
        )
    assert not state_fixture.attempt.exists()


def test_namespace_attempt_intent_and_lock_permissions_are_owner_only(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    with store.claim_submit(initial):
        pass

    namespace = state_fixture.state_root / _NAMESPACE
    directories = (state_fixture.state_root, namespace, state_fixture.attempt)
    directories += (state_fixture.attempt / "revisions",)
    files = (
        namespace / ".create.lock",
        state_fixture.attempt / "lease.lock",
        state_fixture.attempt / "identity.json",
        state_fixture.attempt / "manifest.json",
        state_fixture.attempt / "submit.intent.json",
    )

    for directory in directories:
        metadata = directory.lstat()
        assert stat.S_ISDIR(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o700
        assert metadata.st_uid == os.geteuid()
    for path in files:
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_nlink == 1

    submit_intent = json.loads(files[-1].read_text(encoding="ascii"))
    assert submit_intent["schema_version"] == "1.2"
    assert isinstance(submit_intent["clock_epoch_id"], str)
    assert type(submit_intent["clock_started_boottime_ns"]) is int


@pytest.mark.parametrize("tamper", ["mode", "hardlink", "symlink", "bytes"])
def test_worker_manifest_tampering_blocks_state_adoption(
    state_fixture: StateFixture,
    tamper: str,
) -> None:
    store = _new_store(state_fixture)
    _create(state_fixture, store)
    path = state_fixture.attempt / "manifest.json"
    if tamper == "mode":
        path.chmod(0o640)
    elif tamper == "hardlink":
        os.link(path, state_fixture.attempt / "manifest-alias.json")
    elif tamper == "symlink":
        target = state_fixture.attempt / "manifest-target.json"
        path.rename(target)
        path.symlink_to(target)
    else:
        path.write_bytes(b"{}")
        path.chmod(0o600)

    with pytest.raises(SchedulerStateInvalidError):
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )


def test_submit_intent_restarts_as_unknown_and_cannot_be_claimed_twice(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    with store.claim_submit(initial) as permit:
        assert permit.state.phase == "prepared"
        assert permit.recovery_state.phase == "submit_unknown"
        assert (state_fixture.attempt / "submit.intent.json").is_file()

    restarted_store = _new_store(state_fixture)
    recovered = restarted_store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert recovered.state.phase == "submit_unknown"
    assert recovered.submit_intent_sha256 == permit.intent_sha256

    with (
        pytest.raises(SchedulerStateConflictError) as repeated,
        restarted_store.claim_submit(recovered),
    ):
        pass
    assert repeated.value.reason_code == "SCHEDULER_SUBMIT_ALREADY_CLAIMED"


def test_restart_can_bind_exact_positive_held_evidence_idempotently(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    with store.claim_submit(initial):
        pass
    unknown = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    evidence = _held_job(unknown.state)

    held = store.record_recovered_held(unknown, evidence)
    repeated = store.record_recovered_held(unknown, evidence)

    assert held.state.phase == "held"
    assert held.state.held_job == evidence
    assert repeated.revision == held.revision == 1
    assert repeated.journal_sha256 == held.journal_sha256


def test_mutation_permit_is_single_use_thread_bound_and_invalid_after_context(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    with store.claim_submit(initial) as permit:

        def consume_from_other_thread() -> BaseException | None:
            try:
                _consume(permit, "submit_held", store)
            except BaseException as exc:
                return exc
            return None

        with ThreadPoolExecutor(max_workers=1) as executor:
            cross_thread = executor.submit(consume_from_other_thread).result(timeout=2)
        assert isinstance(cross_thread, SchedulerMutationPermitError)
        assert cross_thread.reason_code == "SCHEDULER_MUTATION_PERMIT_INVALID"

        assert _consume(permit, "submit_held", store) == permit.deadline
        with pytest.raises(SchedulerMutationPermitError):
            _consume(permit, "submit_held", store)

    with pytest.raises(SchedulerMutationPermitError):
        _consume(permit, "submit_held", store)


def test_permit_requires_the_exact_trusted_config_instance(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    reloaded_config = load_trusted_scheduler_config(state_fixture.config_path)
    assert reloaded_config is not store.config
    assert reloaded_config.config_sha256 == store.config.config_sha256

    with store.claim_submit(initial) as permit:
        with pytest.raises(SchedulerMutationPermitError):
            state_module._consume_mutation_permit(
                permit,
                "submit_held",
                permit.state,
                reloaded_config,
            )
        assert _consume(permit, "submit_held", store) == permit.deadline


def test_claim_and_consume_fail_closed_at_the_absolute_deadline(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    before_intent = iter((10.0, 10.0, 11.0))
    with monkeypatch.context() as patch:
        patch.setattr(state_module.time, "monotonic", lambda: next(before_intent))
        with (
            pytest.raises(SchedulerStatePreconditionError) as expired,
            store.claim_submit(initial),
        ):
            pass
    assert expired.value.reason_code == "SCHEDULER_MUTATION_DEADLINE_EXPIRED"
    assert not (state_fixture.attempt / "submit.intent.json").exists()

    live_times = iter((20.0, 20.0, 20.5, 21.0))
    with monkeypatch.context() as patch:
        patch.setattr(state_module.time, "monotonic", lambda: next(live_times))
        with (
            store.claim_submit(initial) as permit,
            pytest.raises(SchedulerMutationPermitError),
        ):
            _consume(permit, "submit_held", store)


def test_wrong_marker_held_evidence_never_creates_a_revision(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    wrong = _wrong_marker_held_job()
    with store.claim_submit(initial) as permit:
        _consume(permit, "submit_held", store)
        with pytest.raises(SchedulerStateContractError):
            store.record_held(permit, wrong, invocation_sha256="e" * 64)

    unknown = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    with pytest.raises(SchedulerStateContractError):
        store.record_recovered_held(unknown, wrong)
    persisted = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert persisted.state.phase == "submit_unknown"
    assert persisted.revision == 0
    assert list((state_fixture.attempt / "revisions").iterdir()) == []


def test_held_revision_is_append_only_and_a_stale_snapshot_loses_cas(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    stale = _create(state_fixture, store)
    held = _held_job(stale.state)
    with store.claim_submit(stale) as permit:
        _consume(permit, "submit_held", store)
        current = store.record_held(
            permit,
            held,
            invocation_sha256="e" * 64,
        )
        repeated = store.record_held(
            permit,
            held,
            invocation_sha256="e" * 64,
        )
        with pytest.raises(SchedulerStateConflictError) as changed_invocation:
            store.record_held(
                permit,
                held,
                invocation_sha256="f" * 64,
            )

    assert current.state.phase == "held"
    assert current.state.held_job == held
    assert current.revision == 1
    assert repeated.revision == current.revision
    assert repeated.journal_sha256 == current.journal_sha256
    assert changed_invocation.value.reason_code == "SCHEDULER_HELD_EVIDENCE_CONFLICT"
    assert sorted((state_fixture.attempt / "revisions").iterdir()) == [
        state_fixture.attempt / "revisions" / "00000000000000000001.json"
    ]

    with (
        pytest.raises(SchedulerStateConflictError) as conflict,
        store.claim_release(stale, elapsed_seconds=1),
    ):
        pass
    assert conflict.value.reason_code == "SCHEDULER_STATE_CAS_CONFLICT"


def test_release_intent_restarts_as_unknown_and_cannot_be_claimed_twice(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1) as permit:
        assert permit.state.phase == "release_ready"
        assert permit.recovery_state.phase == "release_unknown"
        assert (state_fixture.attempt / "release.intent.json").is_file()

    restarted_store = _new_store(state_fixture)
    recovered = restarted_store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert recovered.state.phase == "release_unknown"
    assert recovered.release_intent_sha256 == permit.intent_sha256

    with (
        pytest.raises(SchedulerStateConflictError) as repeated,
        restarted_store.claim_release(recovered, elapsed_seconds=2),
    ):
        pass
    assert repeated.value.reason_code == "SCHEDULER_RELEASE_ALREADY_CLAIMED"


def test_release_success_is_polling_and_the_release_permit_cannot_be_reused(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1) as permit:
        assert _consume(permit, "release_held", store) == permit.deadline
        polling = store.record_release_success(
            permit,
            invocation_sha256="f" * 64,
        )
        repeated = store.record_release_success(
            permit,
            invocation_sha256="f" * 64,
        )
        with pytest.raises(SchedulerStateConflictError) as changed_invocation:
            store.record_release_success(
                permit,
                invocation_sha256="e" * 64,
            )
        with pytest.raises(SchedulerMutationPermitError):
            _consume(permit, "release_held", store)

    assert polling.state.phase == "polling"
    assert repeated.revision == polling.revision == 2
    assert changed_invocation.value.reason_code == "SCHEDULER_RELEASE_EVIDENCE_CONFLICT"
    persisted = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert persisted.state.phase == "polling"
    with (
        pytest.raises(SchedulerStateConflictError) as second_release,
        store.claim_release(persisted, elapsed_seconds=2),
    ):
        pass
    assert second_release.value.reason_code == "SCHEDULER_RELEASE_ALREADY_CLAIMED"


def test_expired_release_is_durably_terminal_without_burning_an_intent(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)

    with (
        pytest.raises(SchedulerStateDeadlineError) as expired,
        store.claim_release(held, elapsed_seconds=10_000),
    ):
        pass

    terminal = expired.value.snapshot
    assert terminal.state.phase == "timed_out"
    assert terminal.revision == 2
    assert terminal.release_intent_sha256 is None
    assert not (state_fixture.attempt / "release.intent.json").exists()
    persisted = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert persisted.state.phase == "timed_out"
    assert persisted.journal_sha256 == terminal.journal_sha256


def test_positive_poll_evidence_recovers_release_unknown_without_releasing_again(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1):
        pass
    recovered = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert recovered.state.phase == "release_unknown"
    assert recovered.state.job is not None

    active = store.record_scheduler_poll(
        recovered,
        queue=SlurmObservation(
            source="squeue",
            job=recovered.state.job,
            state="RUNNING",
        ),
        accounting=None,
        elapsed_seconds=2,
    )
    assert active.state.phase == "polling"

    completed = store.record_scheduler_poll(
        active,
        queue=None,
        accounting=SlurmObservation(
            source="sacct",
            job=active.state.job,
            state="COMPLETED",
            exit_code=(0, 0),
        ),
        elapsed_seconds=3,
    )
    assert completed.state.phase == "awaiting_evidence"
    assert completed.revision == 3


def test_diagnostic_only_active_polls_do_not_consume_revisions(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1):
        pass
    unknown = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert unknown.state.job is not None
    running = store.record_scheduler_poll(
        unknown,
        queue=SlurmObservation(
            source="squeue",
            job=unknown.state.job,
            state="RUNNING",
        ),
        accounting=None,
        elapsed_seconds=2,
    )
    suspended = store.record_scheduler_poll(
        running,
        queue=SlurmObservation(
            source="squeue",
            job=running.state.job,
            state="SUSPENDED",
        ),
        accounting=None,
        elapsed_seconds=3,
    )

    assert running.state.reason_code == "SLURM_RUNNING"
    assert suspended.revision == running.revision
    assert suspended.journal_sha256 == running.journal_sha256


def test_revision_budget_keeps_one_terminal_slot(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1):
        pass
    unknown = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert unknown.state.job is not None
    running = store.record_scheduler_poll(
        unknown,
        queue=SlurmObservation(
            source="squeue",
            job=unknown.state.job,
            state="RUNNING",
        ),
        accounting=None,
        elapsed_seconds=2,
    )
    assert running.revision == 2

    with monkeypatch.context() as patch:
        patch.setattr(state_module, "_MAX_REVISIONS", 3)
        exhausted = store.record_scheduler_poll(
            running,
            queue=None,
            accounting=SlurmObservation(
                source="sacct",
                job=running.state.job,
                state="COMPLETED",
                exit_code=(0, 0),
            ),
            elapsed_seconds=3,
        )
        replayed = store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )

    assert exhausted.state.phase == "indeterminate"
    assert exhausted.state.reason_code == "SCHEDULER_REVISION_BUDGET_EXHAUSTED"
    assert exhausted.revision == 3
    assert replayed.state == exhausted.state
    revision = json.loads(
        (state_fixture.attempt / "revisions" / "00000000000000000003.json").read_text(
            encoding="ascii"
        )
    )
    assert revision["event"] == {"type": "revision_budget_exhausted"}


def test_worker_evidence_read_is_phase_gated_stable_private_and_canonical(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    with pytest.raises(SchedulerStateConflictError):
        store.read_worker_evidence(initial)

    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    with pytest.raises(SchedulerWorkerEvidencePending):
        store.read_worker_evidence(awaiting)
    state = awaiting.state
    value = _worker_evidence_value(state)
    evidence = parse_compute_evidence(value)
    path = state_fixture.attempt / "evidence.json"
    path.write_bytes(canonical_evidence_bytes(evidence))
    path.chmod(0o600)

    assert store.read_worker_evidence(awaiting) == evidence

    path.chmod(0o640)
    with pytest.raises(SchedulerStateInvalidError):
        store.read_worker_evidence(awaiting)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("preflight_id", "other-preflight"),
        ("profile_id", "other-profile"),
        ("profile_hash", "b" * 64),
        ("manifest_sha256", "c" * 64),
        ("worker_sha256", "d" * 64),
        ("job_id", "67890"),
        ("submission_marker", "e" * 64),
    ],
)
def test_worker_evidence_reader_binds_the_current_attempt(
    state_fixture: StateFixture,
    field: str,
    value: str,
) -> None:
    store = _new_store(state_fixture)
    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    evidence_value = _worker_evidence_value(awaiting.state)
    evidence_value[field] = value
    evidence = parse_compute_evidence(evidence_value)
    path = state_fixture.attempt / "evidence.json"
    path.write_bytes(canonical_evidence_bytes(evidence))
    path.chmod(0o600)

    with pytest.raises(SchedulerStateInvalidError):
        store.read_worker_evidence(awaiting)


def test_worker_evidence_ingest_is_self_contained_append_only_and_replayable(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    evidence_path = state_fixture.attempt / "evidence.json"
    value = _worker_evidence_value(awaiting.state)
    evidence_path.write_bytes(canonical_evidence_bytes(parse_compute_evidence(value)))
    evidence_path.chmod(0o600)

    candidate = store.ingest_worker_evidence(awaiting, elapsed_seconds=4)
    assert candidate.state.phase == "candidate"
    assert candidate.state.evidence_sha256 is not None
    assert candidate.revision == awaiting.revision + 1

    revision_path = state_fixture.attempt / "revisions" / f"{candidate.revision:020d}.json"
    revision = json.loads(revision_path.read_text(encoding="ascii"))
    event = revision["event"]
    assert event["type"] == "compute_evidence"
    assert event["evidence"] == value
    assert event["evidence_sha256"] == candidate.state.evidence_sha256

    evidence_path.unlink()
    restarted = _new_store(state_fixture).load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert restarted.state == candidate.state
    assert restarted.journal_sha256 == candidate.journal_sha256


def test_evidence_at_the_exact_overall_deadline_replays_as_timeout(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    evidence_path = state_fixture.attempt / "evidence.json"
    evidence_path.write_bytes(
        canonical_evidence_bytes(parse_compute_evidence(_worker_evidence_value(awaiting.state)))
    )
    evidence_path.chmod(0o600)
    intent = json.loads((state_fixture.attempt / "submit.intent.json").read_text(encoding="ascii"))
    overall = preflight_overall_timeout_seconds(awaiting.state)
    state_fixture.clock.step_ns = 0
    state_fixture.clock.boottime_ns = intent["clock_started_boottime_ns"] + overall * 1_000_000_000

    terminal = store.ingest_worker_evidence(awaiting, elapsed_seconds=0)
    assert terminal.state.phase == "timed_out"
    assert terminal.state.evidence is None
    assert terminal.state.evidence_sha256 is None
    assert terminal.revision == awaiting.revision + 1
    event = json.loads(
        (state_fixture.attempt / "revisions" / f"{terminal.revision:020d}.json").read_text(
            encoding="ascii"
        )
    )["event"]
    assert event == {"type": "driver_timeout", "elapsed_seconds": overall}

    evidence_path.unlink()
    restarted = _new_store(state_fixture).load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert restarted.state == terminal.state
    assert restarted.journal_sha256 == terminal.journal_sha256


def test_compute_evidence_revision_digest_tampering_fails_closed(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    evidence_path = state_fixture.attempt / "evidence.json"
    evidence_path.write_bytes(
        canonical_evidence_bytes(parse_compute_evidence(_worker_evidence_value(awaiting.state)))
    )
    evidence_path.chmod(0o600)
    candidate = store.ingest_worker_evidence(awaiting, elapsed_seconds=4)
    revision_path = state_fixture.attempt / "revisions" / f"{candidate.revision:020d}.json"
    revision = json.loads(revision_path.read_text(encoding="ascii"))
    revision["event"]["evidence_sha256"] = "0" * 64
    _write_canonical(revision_path, revision)

    with pytest.raises(SchedulerStateInvalidError) as captured:
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_STATE_REPLAY_INVALID"


@pytest.mark.parametrize(
    "tamper",
    ["hardlink", "symlink", "noncanonical", "duplicate_key", "oversized"],
)
def test_worker_evidence_reader_rejects_unsafe_or_noncanonical_files(
    state_fixture: StateFixture,
    tamper: str,
) -> None:
    store = _new_store(state_fixture)
    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    evidence = parse_compute_evidence(_worker_evidence_value(awaiting.state))
    path = state_fixture.attempt / "evidence.json"
    path.write_bytes(canonical_evidence_bytes(evidence))
    path.chmod(0o600)

    if tamper == "hardlink":
        os.link(path, state_fixture.attempt / "evidence-alias.json")
    elif tamper == "symlink":
        target = state_fixture.attempt / "evidence-target.json"
        path.rename(target)
        path.symlink_to(target)
    elif tamper == "noncanonical":
        path.write_bytes(b" " + path.read_bytes())
    elif tamper == "duplicate_key":
        path.write_bytes(b'{"evidence_version":"1.0","evidence_version":"1.0"}')
    else:
        path.write_bytes(b"x" * (256 * 1024 + 1))
    if not path.is_symlink():
        path.chmod(0o600)

    with pytest.raises(SchedulerStateInvalidError):
        store.read_worker_evidence(awaiting)


def test_worker_evidence_reader_detects_path_replacement_during_read(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    awaiting = _awaiting_evidence_snapshot(state_fixture, store)
    evidence = parse_compute_evidence(_worker_evidence_value(awaiting.state))
    path = state_fixture.attempt / "evidence.json"
    path.write_bytes(canonical_evidence_bytes(evidence))
    path.chmod(0o600)
    evidence_inode = path.stat().st_ino
    original_read = state_module._read_bounded
    replaced = False

    def replace_after_read(descriptor: int, maximum: int) -> bytes:
        nonlocal replaced
        payload = original_read(descriptor, maximum)
        if not replaced and os.fstat(descriptor).st_ino == evidence_inode:
            path.rename(state_fixture.attempt / "evidence-original.json")
            path.write_bytes(payload)
            path.chmod(0o600)
            replaced = True
        return payload

    monkeypatch.setattr(state_module, "_read_bounded", replace_after_read)
    with pytest.raises(SchedulerStateInvalidError):
        store.read_worker_evidence(awaiting)
    assert replaced is True


@pytest.mark.parametrize("preflight_id", ["../escape", "a/b", ".", "", "a" * 129])
def test_worker_path_derivation_rejects_unsafe_preflight_ids(
    state_fixture: StateFixture,
    preflight_id: str,
) -> None:
    with pytest.raises(SchedulerBindingError):
        expected_worker_paths(state_fixture.config, preflight_id)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b'{"schema_version":"1.0"',
        b"not-json\n",
    ],
)
def test_partial_or_corrupt_submit_intent_fails_closed(
    payload: bytes,
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    snapshot = _create(state_fixture, store)
    intent = state_fixture.attempt / "submit.intent.json"
    intent.write_bytes(payload)
    intent.chmod(0o600)

    with pytest.raises(SchedulerStateInvalidError):
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    with pytest.raises(SchedulerStateInvalidError), store.claim_submit(snapshot):
        pass


def test_partial_release_intent_remains_burned_and_fails_closed(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1):
        pass
    intent = state_fixture.attempt / "release.intent.json"
    intent.write_bytes(b"")
    intent.chmod(0o600)

    with pytest.raises(SchedulerStateInvalidError):
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )


def test_create_only_close_failure_is_commit_unknown(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    _create(state_fixture, store)
    attempt_descriptor = os.open(state_fixture.attempt, os.O_RDONLY)
    real_close = os.close
    record = state_fixture.attempt / "close-failure.json"

    def failed_close(descriptor: int) -> None:
        real_close(descriptor)
        raise OSError("synthetic close failure")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(state_module.os, "close", failed_close)
            with pytest.raises(SchedulerStateCommitUnknown) as unknown:
                state_module._create_record(
                    attempt_descriptor,
                    record.name,
                    {"synthetic": "record"},
                    1024,
                )
    finally:
        real_close(attempt_descriptor)

    assert unknown.value.reason_code == "SCHEDULER_CREATE_ONLY_COMMIT_UNKNOWN"
    assert record.is_file()


@pytest.mark.parametrize("tamper", ["revision", "boolean_revision", "hash", "schema"])
def test_revision_chain_hash_and_schema_tampering_fail_closed(
    tamper: str,
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    revision = state_fixture.attempt / "revisions" / "00000000000000000001.json"
    value = json.loads(revision.read_text(encoding="ascii"))
    if tamper == "revision":
        value["revision"] = 2
    elif tamper == "boolean_revision":
        value["revision"] = True
    elif tamper == "hash":
        value["previous_sha256"] = "f" * 64
    else:
        value["schema_version"] = "9.9"
    _write_canonical(revision, value)

    with pytest.raises(SchedulerStateInvalidError):
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )


def test_revision_reload_failure_is_post_commit_unknown(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)
    with store.claim_submit(initial) as permit:
        _consume(permit, "submit_held", store)
        with monkeypatch.context() as patch:

            def failed_reload(*_args: Any, **_kwargs: Any) -> Any:
                raise SchedulerStateInvalidError("SYNTHETIC_RELOAD_FAILURE", "synthetic")

            patch.setattr(state_module, "_load_attempt", failed_reload)
            with pytest.raises(SchedulerStateCommitUnknown) as unknown:
                store.record_held(
                    permit,
                    _held_job(permit.state),
                    invocation_sha256="e" * 64,
                )

    assert unknown.value.reason_code == "SCHEDULER_REVISION_POST_COMMIT_UNKNOWN"
    persisted = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert persisted.state.phase == "held"
    assert persisted.revision == 1


def test_existing_namespace_is_resynced_before_load(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    _create(state_fixture, store)
    real_fsync = state_module.os.fsync
    calls = 0

    def tracked_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        real_fsync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(state_module.os, "fsync", tracked_fsync)
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert calls >= 2

    with monkeypatch.context() as patch:

        def failed_fsync(_descriptor: int) -> None:
            raise OSError("synthetic directory sync failure")

        patch.setattr(state_module.os, "fsync", failed_fsync)
        with pytest.raises(SchedulerStatePreconditionError) as failed:
            _new_store(state_fixture).load(
                state_fixture.prepared.manifest.preflight_id,
                request_sha256=_REQUEST_SHA256,
            )
    assert failed.value.reason_code == "SCHEDULER_STATE_DIRECTORY_SYNC_FAILED"


@pytest.mark.parametrize(
    "tamper",
    ["identity_mode", "identity_hardlink", "identity_symlink", "lock_mode"],
)
def test_unsafe_identity_or_lock_metadata_fails_closed(
    tamper: str,
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    _create(state_fixture, store)
    identity = state_fixture.attempt / "identity.json"
    lock = state_fixture.attempt / "lease.lock"
    if tamper == "identity_mode":
        identity.chmod(0o644)
    elif tamper == "identity_hardlink":
        os.link(identity, state_fixture.attempt / "identity.link")
    elif tamper == "identity_symlink":
        backup = state_fixture.attempt / "identity.backup"
        identity.rename(backup)
        identity.symlink_to(backup.name)
    else:
        lock.chmod(0o644)

    with pytest.raises(SchedulerStateInvalidError):
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )


@pytest.mark.parametrize("tamper", ["gap", "unexpected_name"])
def test_revision_directory_must_be_bounded_and_contiguous(
    tamper: str,
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    revisions = state_fixture.attempt / "revisions"
    if tamper == "gap":
        (revisions / "00000000000000000001.json").rename(revisions / "00000000000000000002.json")
    else:
        (revisions / "unexpected").write_bytes(b"x")

    with pytest.raises(SchedulerStateInvalidError):
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )


def test_live_attempt_flock_is_busy_across_threads_and_processes(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    initial = _create(state_fixture, store)

    def load_from_other_thread() -> str:
        try:
            _new_store(state_fixture).load(
                state_fixture.prepared.manifest.preflight_id,
                request_sha256=_REQUEST_SHA256,
            )
        except SchedulerStateBusyError as exc:
            return exc.reason_code
        return "loaded"

    source_root = Path(__file__).parents[1] / "src"
    child_code = (
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from bioexec.scheduler_config_loader import load_trusted_scheduler_config\n"
        "from bioexec.scheduler_state import (\n"
        "    SchedulerPreflightStore, SchedulerStateBusyError,\n"
        ")\n"
        "config = load_trusted_scheduler_config(Path(sys.argv[2]))\n"
        "try:\n"
        "    SchedulerPreflightStore(config).load(sys.argv[3], request_sha256=sys.argv[4])\n"
        "except SchedulerStateBusyError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )

    with store.claim_submit(initial):
        with ThreadPoolExecutor(max_workers=1) as executor:
            reason = executor.submit(load_from_other_thread).result(timeout=2)
        assert reason == "SCHEDULER_ATTEMPT_BUSY"

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                child_code,
                str(source_root),
                str(state_fixture.config_path),
                state_fixture.prepared.manifest.preflight_id,
                _REQUEST_SHA256,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert child.returncode == 0, child.stderr


def test_capability_issue_is_hash_only_replayable_and_never_reissued(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    calls = 0

    def token_hex(length: int) -> str:
        nonlocal calls
        calls += 1
        assert length == 32
        return _RAW_CAPABILITY

    monkeypatch.setattr(state_module.secrets, "token_hex", token_hex)
    issued = store.issue_capability(candidate)

    assert calls == 1
    assert issued.preflight_token == _RAW_CAPABILITY
    assert _RAW_CAPABILITY not in repr(issued)
    assert issued.snapshot.state.phase == "passed"
    assert preflight_result(issued.snapshot.state)["preflight_token"] is None
    capability = issued.snapshot.state.capability
    assert capability is not None and not hasattr(capability, "token")
    assert capability.token_hash == hashlib.sha256(_RAW_CAPABILITY.encode("ascii")).hexdigest()
    for path in state_fixture.attempt.rglob("*"):
        if path.is_file():
            assert _RAW_CAPABILITY.encode("ascii") not in path.read_bytes()

    restarted_store = _new_store(state_fixture)
    restarted = restarted_store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert restarted.state == issued.snapshot.state
    with pytest.raises(SchedulerStateConflictError) as captured:
        restarted_store.issue_capability(restarted)
    assert captured.value.reason_code == "SCHEDULER_CAPABILITY_ALREADY_ISSUED"
    assert calls == 1


def test_capability_lost_response_burns_grant_without_disclosing_or_regenerating(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    calls = 0

    def token_hex(length: int) -> str:
        nonlocal calls
        calls += 1
        assert length == 32
        return _RAW_CAPABILITY

    original_append = state_module._append_revision

    def append_then_lose_response(
        config: TrustedSchedulerConfig,
        opened: Any,
        loaded: Any,
        event: Any,
    ) -> Any:
        committed = original_append(config, opened, loaded, event)
        if event.get("type") == "capability_issued":
            raise SchedulerStateCommitUnknown(
                "SCHEDULER_TEST_POST_COMMIT_UNKNOWN",
                "synthetic lost issuance response",
            )
        return committed

    monkeypatch.setattr(state_module.secrets, "token_hex", token_hex)
    monkeypatch.setattr(state_module, "_append_revision", append_then_lose_response)
    with pytest.raises(SchedulerStateCommitUnknown):
        store.issue_capability(candidate)
    assert calls == 1

    monkeypatch.setattr(state_module, "_append_revision", original_append)
    restarted_store = _new_store(state_fixture)
    burned = restarted_store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert burned.state.phase == "passed"
    assert burned.state.capability is not None
    assert preflight_result(burned.state)["preflight_token"] is None
    with pytest.raises(SchedulerStateConflictError) as captured:
        restarted_store.issue_capability(burned)
    assert captured.value.reason_code == "SCHEDULER_CAPABILITY_ALREADY_ISSUED"
    assert calls == 1
    for path in state_fixture.attempt.rglob("*"):
        if path.is_file():
            assert _RAW_CAPABILITY.encode("ascii") not in path.read_bytes()


def test_capability_post_commit_clock_failure_burns_without_returning_raw(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    samples = 0
    original_sample = state_fixture.clock.sample

    def discontinuous_second_sample() -> ClockSample:
        nonlocal samples
        samples += 1
        sample = original_sample()
        if samples == 2:
            return ClockSample(epoch_id="next-boot", boottime_ns=sample.boottime_ns)
        return sample

    monkeypatch.setattr(state_fixture.clock, "sample", discontinuous_second_sample)
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    with pytest.raises(SchedulerClockDiscontinuityError) as captured:
        store.issue_capability(candidate)
    invalidated = captured.value.snapshot
    assert invalidated.state.phase == "indeterminate"
    assert invalidated.state.capability is not None
    assert preflight_result(invalidated.state)["preflight_token"] is None
    for path in state_fixture.attempt.rglob("*"):
        if path.is_file():
            assert _RAW_CAPABILITY.encode("ascii") not in path.read_bytes()


def test_capability_issue_concurrency_generates_and_returns_only_one_token(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    creator = _new_store(state_fixture)
    _candidate_snapshot(state_fixture, creator)
    stores = (_new_store(state_fixture), _new_store(state_fixture))
    snapshots = tuple(
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
        for store in stores
    )
    calls = 0
    calls_lock = threading.Lock()

    def token_hex(length: int) -> str:
        nonlocal calls
        assert length == 32
        with calls_lock:
            calls += 1
        return _RAW_CAPABILITY

    def issue(index: int) -> tuple[str, str | None]:
        try:
            response = stores[index].issue_capability(snapshots[index])
        except (SchedulerStateBusyError, SchedulerStateConflictError) as exc:
            return "rejected", exc.reason_code
        return "issued", response.preflight_token

    monkeypatch.setattr(state_module.secrets, "token_hex", token_hex)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(issue, range(2)))

    assert sum(status == "issued" for status, _ in results) == 1
    assert [value for status, value in results if status == "issued"] == [_RAW_CAPABILITY]
    assert calls == 1
    current = _new_store(state_fixture).load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert current.state.phase == "passed"
    assert current.state.capability is not None


def test_capability_consumption_is_atomic_bound_and_replayable(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuing_store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, issuing_store)
    monkeypatch.setattr(
        state_module.secrets,
        "token_hex",
        lambda length: _RAW_CAPABILITY if length == 32 else "",
    )
    issued = issuing_store.issue_capability(candidate)
    stores = (_new_store(state_fixture), _new_store(state_fixture))
    snapshots = tuple(
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
        for store in stores
    )

    def consume(index: int) -> tuple[str, str | None]:
        try:
            consumed = stores[index].consume_capability(
                snapshots[index],
                token=_RAW_CAPABILITY,
                consumed_by="run-1",
                consumer_binding_hash=_CONSUMER_BINDING_HASH,
            )
        except (SchedulerStateBusyError, SchedulerStateConflictError) as exc:
            return "rejected", exc.reason_code
        assert consumed.state.capability is not None
        return "consumed", consumed.state.capability.binding_hash

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(consume, range(2)))
    assert sum(status == "consumed" for status, _ in results) == 1

    restarted_store = _new_store(state_fixture)
    restarted = restarted_store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    capability = restarted.state.capability
    assert capability is not None and capability.consumed
    assert capability.consumed_by == "run-1"
    assert capability.consumer_binding_hash == _CONSUMER_BINDING_HASH
    assert restarted.revision == issued.snapshot.revision + 1
    with pytest.raises(SchedulerStateConflictError) as captured:
        restarted_store.consume_capability(
            restarted,
            token=_RAW_CAPABILITY,
            consumed_by="run-2",
            consumer_binding_hash="f" * 64,
        )
    assert captured.value.reason_code == "SCHEDULER_CAPABILITY_ALREADY_CONSUMED"


def test_wrong_capability_token_never_writes_a_revision(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    issued = store.issue_capability(candidate)

    with pytest.raises(SchedulerStatePreconditionError) as captured:
        store.consume_capability(
            issued.snapshot,
            token="f" * 64,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
        )
    assert captured.value.reason_code == "SCHEDULER_CAPABILITY_INVALID"
    unchanged = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert unchanged.revision == issued.snapshot.revision
    assert unchanged.state.capability is not None
    assert not unchanged.state.capability.consumed


def test_capability_exact_expiry_is_irreversible_and_uses_trusted_clock(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    issued = store.issue_capability(candidate)
    capability = issued.snapshot.state.capability
    assert capability is not None
    intent = json.loads((state_fixture.attempt / "submit.intent.json").read_text("ascii"))
    state_fixture.clock.step_ns = 0
    state_fixture.clock.boottime_ns = (
        intent["clock_started_boottime_ns"] + capability.expires_at * 1_000_000_000
    )

    with pytest.raises(SchedulerCapabilityExpiredError) as captured:
        store.consume_capability(
            issued.snapshot,
            token=_RAW_CAPABILITY,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
        )
    expired = captured.value.snapshot
    assert expired.state.phase == "timed_out"
    assert expired.state.reason_code == "COMPUTE_PREFLIGHT_CAPABILITY_EXPIRED"
    assert expired.state.capability is not None and expired.state.capability.expired
    assert expired.state.capability.expired_at == capability.expires_at
    restarted = _new_store(state_fixture).load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert restarted.state == expired.state


def test_capability_issue_capacity_failure_happens_before_rng(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)

    def forbidden_rng(length: int) -> str:
        raise AssertionError(f"RNG called before preconditions: {length}")

    monkeypatch.setattr(state_module.secrets, "token_hex", forbidden_rng)
    monkeypatch.setattr(state_module, "_MAX_REVISIONS", candidate.revision + 1)
    with pytest.raises(SchedulerCapabilityUnavailableError):
        store.issue_capability(candidate)
    terminal = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert terminal.state.phase == "indeterminate"
    assert terminal.state.reason_code == "SCHEDULER_REVISION_BUDGET_EXHAUSTED"


def test_capability_issue_deadline_failure_happens_before_rng(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    intent = json.loads((state_fixture.attempt / "submit.intent.json").read_text("ascii"))
    overall = preflight_overall_timeout_seconds(candidate.state)
    state_fixture.clock.step_ns = 0
    state_fixture.clock.boottime_ns = intent["clock_started_boottime_ns"] + overall * 1_000_000_000

    def forbidden_rng(length: int) -> str:
        raise AssertionError(f"RNG called after deadline: {length}")

    monkeypatch.setattr(state_module.secrets, "token_hex", forbidden_rng)
    with pytest.raises(SchedulerCapabilityUnavailableError) as captured:
        store.issue_capability(candidate)
    assert captured.value.snapshot.state.phase == "timed_out"
    assert captured.value.snapshot.state.capability is None


def test_capability_post_commit_exact_overall_deadline_burns_without_response(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    intent = json.loads((state_fixture.attempt / "submit.intent.json").read_text("ascii"))
    overall = preflight_overall_timeout_seconds(candidate.state)
    state_fixture.clock.step_ns = 1_000_000_000
    state_fixture.clock.boottime_ns = (
        intent["clock_started_boottime_ns"] + (overall - 1) * 1_000_000_000
    )
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)

    with pytest.raises(SchedulerCapabilityUnavailableError) as captured:
        store.issue_capability(candidate)
    timed_out = captured.value.snapshot
    assert timed_out.state.phase == "timed_out"
    assert timed_out.state.reason_code == "SLURM_PREFLIGHT_OVERALL_TIMEOUT"
    assert timed_out.state.capability is not None
    assert not timed_out.state.capability.consumed
    assert preflight_result(timed_out.state)["preflight_token"] is None
    last_event = json.loads(
        (state_fixture.attempt / "revisions" / f"{timed_out.revision:020d}.json").read_text("ascii")
    )["event"]
    assert last_event == {"type": "driver_timeout", "elapsed_seconds": overall}
    for path in state_fixture.attempt.rglob("*"):
        if path.is_file():
            assert _RAW_CAPABILITY.encode("ascii") not in path.read_bytes()


def test_disclosed_capability_uses_its_ttl_after_overall_preflight_deadline(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    intent = json.loads((state_fixture.attempt / "submit.intent.json").read_text("ascii"))
    overall = preflight_overall_timeout_seconds(candidate.state)
    started_ns = intent["clock_started_boottime_ns"]
    state_fixture.clock.step_ns = 1_000_000_000
    state_fixture.clock.boottime_ns = started_ns + (overall - 2) * 1_000_000_000
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    issued = store.issue_capability(candidate)
    capability = issued.snapshot.state.capability
    assert capability is not None and capability.expires_at > overall

    state_fixture.clock.step_ns = 0
    state_fixture.clock.boottime_ns = started_ns + overall * 1_000_000_000
    consumed = store.consume_capability(
        issued.snapshot,
        token=_RAW_CAPABILITY,
        consumed_by="run-1",
        consumer_binding_hash=_CONSUMER_BINDING_HASH,
    )
    assert consumed.state.capability is not None
    assert consumed.state.capability.consumed
    assert consumed.state.capability.consumed_at == overall


def test_capability_clock_epoch_change_invalidates_before_consumption(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    issued = store.issue_capability(candidate)
    state_fixture.clock.epoch_id = "next-boot"

    with pytest.raises(SchedulerClockDiscontinuityError) as captured:
        store.consume_capability(
            issued.snapshot,
            token=_RAW_CAPABILITY,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
        )
    invalidated = captured.value.snapshot
    assert invalidated.state.phase == "indeterminate"
    assert invalidated.state.reason_code == "SCHEDULER_CLOCK_DISCONTINUITY"
    assert invalidated.state.capability is not None
    assert not invalidated.state.capability.consumed


def test_capability_consume_commit_unknown_never_returns_success_and_cannot_replay(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    issued = store.issue_capability(candidate)
    original_append = state_module._append_revision

    def append_then_lose_response(
        config: TrustedSchedulerConfig,
        opened: Any,
        loaded: Any,
        event: Any,
    ) -> Any:
        committed = original_append(config, opened, loaded, event)
        if event.get("type") == "capability_consumed":
            raise SchedulerStateCommitUnknown(
                "SCHEDULER_TEST_CONSUME_POST_COMMIT_UNKNOWN",
                "synthetic lost consumption response",
            )
        return committed

    monkeypatch.setattr(state_module, "_append_revision", append_then_lose_response)
    with pytest.raises(SchedulerStateCommitUnknown):
        store.consume_capability(
            issued.snapshot,
            token=_RAW_CAPABILITY,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
        )

    monkeypatch.setattr(state_module, "_append_revision", original_append)
    restarted_store = _new_store(state_fixture)
    consumed = restarted_store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert consumed.state.capability is not None and consumed.state.capability.consumed
    with pytest.raises(SchedulerStateConflictError) as captured:
        restarted_store.consume_capability(
            consumed,
            token=_RAW_CAPABILITY,
            consumed_by="run-1",
            consumer_binding_hash=_CONSUMER_BINDING_HASH,
        )
    assert captured.value.reason_code == "SCHEDULER_CAPABILITY_ALREADY_CONSUMED"


@pytest.mark.parametrize("field", ["token_hash", "expires_at", "grant_binding_hash"])
def test_capability_issuance_event_tampering_fails_replay(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, store)
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: _RAW_CAPABILITY)
    issued = store.issue_capability(candidate)
    revision_path = state_fixture.attempt / "revisions" / f"{issued.snapshot.revision:020d}.json"
    revision = json.loads(revision_path.read_text(encoding="ascii"))
    revision["event"][field] = revision["event"][field] + 1 if field == "expires_at" else "f" * 64
    _write_canonical(revision_path, revision)

    with pytest.raises(SchedulerStateInvalidError) as captured:
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_STATE_REPLAY_INVALID"


def test_python39_v1_import_graph_does_not_load_scheduler_state() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "import bioexec.main\n"
        "import bioexec.config\n"
        "import bioexec.protocol\n"
        "import bioexec.preflight\n"
        "import bioexec.deployment\n"
        "import bioexec.runner\n"
        "import bioexec.state\n"
        "import bioexec.commands\n"
        "assert 'bioexec.scheduler_state' not in sys.modules\n"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
