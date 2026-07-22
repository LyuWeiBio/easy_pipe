"""Durability and recovery tests for the dormant M7 scheduler state store."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_state as state_module
from bioexec.scheduler_config_loader import (
    TrustedSchedulerConfig,
    load_trusted_scheduler_config,
)
from bioexec.scheduler_preflight import (
    SchedulerPreflightState,
    input_set_hash,
    parse_compute_manifest,
    prepare_preflight,
)
from bioexec.scheduler_state import (
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
)
from bioexec.slurm import SlurmHeldJob, SlurmJobRef, SlurmObservation

_REQUEST_SHA256 = "9" * 64
_PROFILE_HASH = "a" * 64
_SUBMITTED_AT = "2026-07-19T12:34:56"
_JOB_ID = "12345"
_NAMESPACE = "scheduler-preflights-v1"


@dataclass(frozen=True)
class StateFixture:
    config: TrustedSchedulerConfig
    config_path: Path
    prepared: SchedulerPreflightState
    state_root: Path

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
        "java",
        "nextflow",
        "apptainer",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o700)
    executables = {role: bin_dir / role for role in executable_roles}
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

    worker_dir = roots["state"] / "preflight-1"
    worker_dir.mkdir(mode=0o700)
    execution_paths = (str(roots["read"] / "sample_R1.fastq.gz"),)
    manifest_value: dict[str, Any] = {
        "manifest_version": "1.0",
        "preflight_id": "preflight-1",
        "profile_version": "2.0",
        "profile_id": config.contract.profile_id,
        "profile_hash": config.contract.profile_hash,
        "scheduler_policy_hash": config.scheduler_policy_hash,
        "scheduler_policy": policy,
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
        "minimum_free_bytes": 1024 * 1024,
        "network_disabled": True,
        "resume_run_id": None,
        "preflight_ttl_seconds": 900,
        "worker": {
            "contract_version": "1.0",
            "executable": str(worker_dir / "bioexec-compute-preflight"),
            "executable_sha256": "d" * 64,
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
    )


def _new_store(fixture: StateFixture) -> SchedulerPreflightStore:
    return SchedulerPreflightStore(fixture.config)


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
    before_intent = iter((10.0, 11.0))
    with monkeypatch.context() as patch:
        patch.setattr(state_module.time, "monotonic", lambda: next(before_intent))
        with (
            pytest.raises(SchedulerStatePreconditionError) as expired,
            store.claim_submit(initial),
        ):
            pass
    assert expired.value.reason_code == "SCHEDULER_MUTATION_DEADLINE_EXPIRED"
    assert not (state_fixture.attempt / "submit.intent.json").exists()

    live_times = iter((20.0, 20.5, 21.0))
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
