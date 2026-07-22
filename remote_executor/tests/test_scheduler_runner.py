"""Adversarial transport and durable-permit tests for the dormant M7 adapter."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from itertools import count
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_preflight as preflight_module
import bioexec.scheduler_runner as runner_module
from bioexec.scheduler_config_loader import (
    TrustedSchedulerConfig,
    load_trusted_scheduler_config,
)
from bioexec.scheduler_preflight import (
    SchedulerPreflightState,
    input_set_hash,
    parse_compute_manifest,
    prepare_preflight,
    record_held_release,
    record_held_submission,
    record_release_intent,
    record_scheduler_poll,
)
from bioexec.scheduler_runner import (
    SchedulerCommandStartError,
    SchedulerMutationUnknown,
    SchedulerQueryEvidenceError,
    SchedulerQueryRetryableError,
    SchedulerRunnerAdapter,
    SchedulerRunnerContractError,
    SchedulerRunnerPreconditionError,
)
from bioexec.scheduler_state import (
    SchedulerMutationPermit,
    SchedulerPreflightStore,
    SchedulerStateContractError,
    SchedulerStateSnapshot,
)
from bioexec.slurm import SlurmHeldJob, SlurmJobRef

_SUBMITTED_AT = "2026-07-19T12:34:56"
_JOB_ID = "12345"
_PROFILE_HASH = "a" * 64
_ATTEMPT_SEQUENCE = count(1)


@dataclass(frozen=True)
class RunnerFixture:
    config: TrustedSchedulerConfig
    adapter: SchedulerRunnerAdapter
    prepared: SchedulerPreflightState
    state_root: Path
    executables: dict[str, Path]

    def scenario(self, **values: Any) -> None:
        defaults: dict[str, Any] = {
            "stdout_hex": "",
            "stderr_hex": "",
            "exit_code": 0,
            "sleep_seconds": 0,
            "read_stdin": True,
            "spawn_descendant": False,
        }
        defaults.update(values)
        (self.state_root / "scenario.json").write_text(
            json.dumps(defaults, allow_nan=False, separators=(",", ":")),
            encoding="utf-8",
        )

    def record(self) -> dict[str, Any]:
        return json.loads((self.state_root / "record.json").read_text(encoding="utf-8"))


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


def _command_script() -> bytes:
    source = f"""#!{sys.executable}
import hashlib
import json
import os
import subprocess
import sys
import time

home = os.environ["HOME"]
with open(os.path.join(home, "scenario.json"), "r", encoding="utf-8") as handle:
    scenario = json.load(handle)
stdin = sys.stdin.buffer.read() if scenario.get("read_stdin", True) else b""
record = {{
    "argv": sys.argv[1:],
    "env": dict(os.environ),
    "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
    "stdin_size": len(stdin),
}}
if scenario.get("spawn_descendant", False):
    descendant_sleep = float(scenario.get("descendant_sleep_seconds", 60))
    descendant = subprocess.Popen(
        [sys.executable, "-c", f"import time; time.sleep({{descendant_sleep!r}})"],
        stdin=subprocess.DEVNULL,
        stdout=sys.stdout,
        stderr=sys.stderr,
        close_fds=True,
        start_new_session=bool(scenario.get("escape_descendant", False)),
    )
    record["descendant_pid"] = descendant.pid
with open(os.path.join(home, "record.json"), "w", encoding="utf-8") as handle:
    json.dump(record, handle, sort_keys=True)
time.sleep(float(scenario.get("sleep_seconds", 0)))
sys.stdout.buffer.write(bytes.fromhex(scenario.get("stdout_hex", "")))
sys.stdout.buffer.flush()
sys.stderr.buffer.write(bytes.fromhex(scenario.get("stderr_hex", "")))
sys.stderr.buffer.flush()
raise SystemExit(int(scenario.get("exit_code", 0)))
"""
    return source.encode("utf-8")


def _write_executable(path: Path) -> None:
    path.write_bytes(_command_script())
    path.chmod(0o755)


@pytest.fixture
def runner_fixture(tmp_path: Path) -> RunnerFixture:
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
        "submit_timeout_seconds": 2,
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
            "command_timeout_seconds": 2.0,
        },
    }
    config_path = tmp_path / "scheduler-config.json"
    config_path.write_text(
        json.dumps(config_value, allow_nan=False, ensure_ascii=True, separators=(",", ":")),
        encoding="utf-8",
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
    fixture = RunnerFixture(
        config=config,
        adapter=SchedulerRunnerAdapter(config),
        prepared=prepared,
        state_root=roots["state"],
        executables=executables,
    )
    fixture.scenario()
    return fixture


def _hex(value: bytes) -> str:
    return value.hex()


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


def _release_ready(state: SchedulerPreflightState) -> SchedulerPreflightState:
    held = record_held_submission(state, _held_job(state))
    return record_release_intent(held, elapsed_seconds=1)


def _polling(state: SchedulerPreflightState) -> SchedulerPreflightState:
    return record_held_release(_release_ready(state))


def _fresh_prepared(
    fixture: RunnerFixture,
    state: SchedulerPreflightState | None = None,
) -> SchedulerPreflightState:
    basis = fixture.prepared if state is None else state
    preflight_id = f"runner-{next(_ATTEMPT_SEQUENCE)}"
    worker_dir = fixture.state_root / "scheduler-preflights-v1" / preflight_id
    manifest = replace(
        basis.manifest,
        preflight_id=preflight_id,
        worker=replace(
            basis.manifest.worker,
            manifest_path=str(worker_dir / "manifest.json"),
            evidence_path=str(worker_dir / "evidence.json"),
        ),
    )
    return prepare_preflight(manifest)


def _request_sha256(state: SchedulerPreflightState) -> str:
    return hashlib.sha256(f"runner-test:{state.manifest_sha256}".encode("ascii")).hexdigest()


@contextmanager
def _submit_claim(
    fixture: RunnerFixture,
    state: SchedulerPreflightState | None = None,
) -> Iterator[tuple[SchedulerPreflightStore, SchedulerStateSnapshot, SchedulerMutationPermit]]:
    prepared = _fresh_prepared(fixture, state)
    store = SchedulerPreflightStore(fixture.config)
    snapshot = store.create_or_load(prepared, request_sha256=_request_sha256(prepared))
    with store.claim_submit(snapshot) as permit:
        yield store, snapshot, permit


@contextmanager
def _release_claim(
    fixture: RunnerFixture,
) -> Iterator[tuple[SchedulerPreflightStore, SchedulerStateSnapshot, SchedulerMutationPermit]]:
    prepared = _fresh_prepared(fixture)
    store = SchedulerPreflightStore(fixture.config)
    request_sha256 = _request_sha256(prepared)
    snapshot = store.create_or_load(prepared, request_sha256=request_sha256)
    with store.claim_submit(snapshot):
        pass
    unknown = store.load(prepared.manifest.preflight_id, request_sha256=request_sha256)
    held = store.record_recovered_held(unknown, _held_job(unknown.state))
    with store.claim_release(held, elapsed_seconds=1) as permit:
        yield store, held, permit


def test_only_six_fixed_public_adapter_methods_exist() -> None:
    methods = {
        name
        for name, value in inspect.getmembers(SchedulerRunnerAdapter, inspect.isfunction)
        if not name.startswith("_")
    }
    assert methods == {
        "submit_held",
        "query_held",
        "discover_submit",
        "release_held",
        "query_queue",
        "query_accounting",
    }


def test_submit_uses_exact_template_fixed_argv_minimal_env_and_adjacent_rechecks(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    fixture.scenario(stdout_hex=_hex(f"{_JOB_ID}\n".encode("ascii")))
    events: list[str] = []
    popen_kwargs: dict[str, Any] = {}
    real_config = runner_module.verify_scheduler_config_file
    real_root = runner_module.verify_scheduler_root
    real_executable = runner_module.verify_scheduler_executable
    real_popen = runner_module.subprocess.Popen
    captured_results: list[runner_module.SchedulerCommandResult] = []
    real_execute = runner_module._execute_invocation

    def checked_config(config: TrustedSchedulerConfig) -> None:
        events.append("config")
        real_config(config)

    def checked_root(config: TrustedSchedulerConfig, role: str, index: int = 0) -> None:
        events.append("root")
        real_root(config, role, index)  # type: ignore[arg-type]

    def checked_executable(config: TrustedSchedulerConfig, role: str) -> None:
        events.append("executable")
        real_executable(config, role)  # type: ignore[arg-type]

    def checked_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        events.append("popen")
        popen_kwargs.update(kwargs)
        return real_popen(*args, **kwargs)

    def capture_result(
        config: TrustedSchedulerConfig,
        invocation: runner_module._Invocation,
    ) -> runner_module.SchedulerCommandResult:
        result = real_execute(config, invocation)
        captured_results.append(result)
        return result

    monkeypatch.setattr(runner_module, "verify_scheduler_config_file", checked_config)
    monkeypatch.setattr(runner_module, "verify_scheduler_root", checked_root)
    monkeypatch.setattr(runner_module, "verify_scheduler_executable", checked_executable)
    monkeypatch.setattr(runner_module.subprocess, "Popen", checked_popen)
    monkeypatch.setattr(runner_module, "_execute_invocation", capture_result)

    with _submit_claim(fixture) as (_store, _snapshot, permit):
        state = permit.state
        job = fixture.adapter.submit_held(state, permit=permit)

    assert job.job_id == _JOB_ID
    assert events[0] == "config"
    assert events[-2:] == ["executable", "popen"]
    assert events[1:-2] and set(events[1:-2]) == {"root"}
    assert popen_kwargs["shell"] is False
    assert popen_kwargs["text"] is False
    assert popen_kwargs["close_fds"] is True
    assert popen_kwargs["start_new_session"] is True
    assert popen_kwargs["env"] == {
        "HOME": str(fixture.state_root),
        "LANG": "C",
        "LC_ALL": "C",
    }
    assert "PATH" not in popen_kwargs["env"]
    record = fixture.record()
    assert record["stdin_size"] == len(state.template_bytes)
    assert record["stdin_sha256"] == state.template_sha256
    assert "--hold" in record["argv"]
    assert "--parsable" in record["argv"]
    assert not any("--wrap" in value or "scancel" in value for value in record["argv"])
    result = captured_results[0]
    assert result.stdout == f"{_JOB_ID}\n".encode("ascii")
    assert result.stderr == b""
    assert result.stdin_sha256 == state.template_sha256
    assert result.stdin_size == len(state.template_bytes)
    assert result.stdin_bytes_written == result.stdin_size
    assert result.transport_complete is True


def test_all_six_operations_parse_only_strict_successful_transport(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    with _submit_claim(fixture) as (store, _snapshot, submit_permit):
        state = submit_permit.state
        marker = state.submission_marker
        fixture.scenario(stdout_hex=_hex(f"{_JOB_ID}\n".encode("ascii")))
        provisional = fixture.adapter.submit_held(state, permit=submit_permit)

        hold_row = f"{_JOB_ID}|{_SUBMITTED_AT}|{marker}|PENDING|JobHeldUser\n"
        fixture.scenario(stdout_hex=_hex(hold_row.encode("ascii")))
        held = fixture.adapter.query_held(state, provisional)
        assert held == _held_job(state)
        held_snapshot = store.record_held(submit_permit, held)

    unknown = submit_permit.recovery_state
    discovery_row = f"{_JOB_ID}|{_SUBMITTED_AT}|{marker}|PENDING\n"
    fixture.scenario(stdout_hex=_hex(discovery_row.encode("ascii")))
    discovered = fixture.adapter.discover_submit(unknown)
    assert discovered is not None and discovered.job == _held_job(state).job

    with store.claim_release(held_snapshot, elapsed_seconds=1) as release_permit:
        fixture.scenario()
        receipt = fixture.adapter.release_held(release_permit.state, permit=release_permit)
        assert receipt.operation == "release_held"
        polling_snapshot = store.record_release_success(
            release_permit,
            invocation_sha256=receipt.invocation_sha256,
        )

    polling = polling_snapshot.state
    queue_row = f"{_JOB_ID}|{_SUBMITTED_AT}|{marker}|RUNNING\n"
    fixture.scenario(stdout_hex=_hex(queue_row.encode("ascii")))
    queue = fixture.adapter.query_queue(polling)
    assert queue is not None and queue.state == "RUNNING"

    accounting_row = f"{_JOB_ID}|{_SUBMITTED_AT}|{marker}|COMPLETED|0:0\n"
    fixture.scenario(stdout_hex=_hex(accounting_row.encode("ascii")))
    accounting = fixture.adapter.query_accounting(polling)
    assert accounting is not None and accounting.exit_code == (0, 0)
    assert fixture.record()["stdin_size"] == 0


@pytest.mark.parametrize(
    ("scenario", "reason_code"),
    [
        ({"exit_code": 9}, "SCHEDULER_MUTATION_EXIT_NONZERO"),
        ({"stderr_hex": _hex(b"warning\n")}, "SCHEDULER_MUTATION_STDERR_NONEMPTY"),
        ({"stdout_hex": _hex(b"not-a-job-id\n")}, "SCHEDULER_SUBMIT_OUTPUT_INVALID"),
        ({"sleep_seconds": 3}, "SCHEDULER_MUTATION_TRANSPORT_INCOMPLETE"),
        (
            {"stdout_hex": _hex(b"a" * 600), "stderr_hex": _hex(b"b" * 600)},
            "SCHEDULER_MUTATION_TRANSPORT_INCOMPLETE",
        ),
    ],
)
def test_submit_post_start_failures_are_sanitized_mutation_unknown(
    runner_fixture: RunnerFixture,
    scenario: dict[str, Any],
    reason_code: str,
) -> None:
    fixture = runner_fixture
    fixture.scenario(**scenario)

    with _submit_claim(fixture) as (_store, _snapshot, permit):  # noqa: SIM117
        with pytest.raises(SchedulerMutationUnknown) as captured:
            fixture.adapter.submit_held(permit.state, permit=permit)

    error = captured.value
    assert error.reason_code == reason_code
    assert len(error.invocation_sha256) == 64
    assert error.stdin_sha256 == permit.state.template_sha256
    assert not hasattr(error, "stdout")
    assert "#!/bin/sh" not in str(error)
    assert "HOME" not in str(error)


def test_submit_incomplete_stdin_is_mutation_unknown(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    fixture.scenario(stdout_hex=_hex(f"{_JOB_ID}\n".encode("ascii")))

    def failed_writer(_descriptor: int, _data: Any) -> int:
        raise BrokenPipeError("synthetic scheduler stdin failure")

    with _submit_claim(fixture) as (_store, _snapshot, permit):
        monkeypatch.setattr(runner_module.os, "write", failed_writer)
        with pytest.raises(SchedulerMutationUnknown) as captured:
            fixture.adapter.submit_held(permit.state, permit=permit)

    assert captured.value.io_failed is True
    assert captured.value.stdin_bytes_written == 0
    assert captured.value.stdin_size == len(permit.state.template_bytes)


def test_release_post_start_anomalies_are_never_reported_as_success(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture

    for scenario in (
        {"stdout_hex": _hex(b"released\n")},
        {"stderr_hex": _hex(b"warning\n")},
        {"exit_code": 1},
        {"sleep_seconds": 3},
    ):
        fixture.scenario(**scenario)
        with _release_claim(fixture) as (_store, _snapshot, permit):  # noqa: SIM117
            with pytest.raises(SchedulerMutationUnknown):
                fixture.adapter.release_held(permit.state, permit=permit)


def test_pre_popen_start_error_is_distinct_from_post_start_unknown(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture

    def cannot_start(*_args: Any, **_kwargs: Any) -> subprocess.Popen[bytes]:
        raise OSError("synthetic exec failure")

    monkeypatch.setattr(runner_module.subprocess, "Popen", cannot_start)

    with _submit_claim(fixture) as (_store, _snapshot, permit):  # noqa: SIM117
        with pytest.raises(SchedulerCommandStartError) as captured:
            fixture.adapter.submit_held(permit.state, permit=permit)
    assert not isinstance(captured.value, SchedulerMutationUnknown)
    assert len(captured.value.invocation_sha256) == 64


@pytest.mark.parametrize(
    "role",
    [
        "sbatch",
        "python",
        "java",
        "nextflow",
        "nextflow_jar",
        "apptainer",
        "compute_worker",
    ],
)
def test_trusted_recheck_failure_is_precondition_not_start_or_unknown(
    runner_fixture: RunnerFixture,
    role: str,
) -> None:
    fixture = runner_fixture
    with _submit_claim(fixture) as (_store, _snapshot, permit):
        if role == "nextflow_jar":
            changed = fixture.config.nextflow_jar.path
            changed.chmod(0o644)
            changed.write_bytes(b"changed after startup")
            changed.chmod(0o444)
        else:
            fixture.executables[role].write_bytes(b"changed after startup")
            fixture.executables[role].chmod(0o755)

        with pytest.raises(SchedulerRunnerPreconditionError):
            fixture.adapter.submit_held(permit.state, permit=permit)


@pytest.mark.parametrize(
    "scenario",
    [
        {"exit_code": 1},
        {"stderr_hex": _hex(b"failure\n")},
        {"sleep_seconds": 3},
        {"stdout_hex": _hex(b"a" * 600), "stderr_hex": _hex(b"b" * 600)},
    ],
)
def test_failed_empty_or_incomplete_query_is_retryable_not_missing(
    runner_fixture: RunnerFixture,
    scenario: dict[str, Any],
) -> None:
    fixture = runner_fixture
    fixture.scenario(**scenario)

    with pytest.raises(SchedulerQueryRetryableError):
        fixture.adapter.query_queue(_polling(fixture.prepared))


def test_only_clean_empty_query_means_no_row_and_malformed_row_is_evidence_error(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    state = _polling(fixture.prepared)

    fixture.scenario()
    assert fixture.adapter.query_queue(state) is None

    fixture.scenario(stdout_hex=_hex(b"malformed\n"))
    with pytest.raises(SchedulerQueryEvidenceError):
        fixture.adapter.query_queue(state)


def test_global_output_limit_is_shared_across_stdout_and_stderr(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    fixture.scenario(stdout_hex=_hex(b"a" * 600), stderr_hex=_hex(b"b" * 600))
    state = _polling(fixture.prepared)
    invocation = runner_module._make_invocation(
        fixture.config,
        operation="query_queue",
        argv=runner_module.build_squeue_argv(
            str(fixture.config.executables["squeue"].path),
            state.job,
        ),
        stdin_bytes=None,
        timeout_seconds=1.0,
        state=state,
    )

    result = runner_module._execute_invocation(fixture.config, invocation)

    assert result.output_limit_exceeded is True
    assert len(result.stdout) + len(result.stderr) == 1024
    assert result.transport_complete is False


def test_descendant_holding_pipes_is_bounded_and_retryable(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    fixture.scenario(spawn_descendant=True)
    started = runner_module.time.monotonic()

    with pytest.raises(SchedulerQueryRetryableError):
        fixture.adapter.query_queue(_polling(fixture.prepared))

    assert runner_module.time.monotonic() - started < 2.0


def test_phase_job_and_marker_mismatches_fail_before_process_start(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    started = False

    def unexpected_start(*_args: Any, **_kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal started
        started = True
        raise AssertionError("Popen must not run")

    monkeypatch.setattr(runner_module.subprocess, "Popen", unexpected_start)
    with _release_claim(fixture) as (  # noqa: SIM117
        _store,
        _snapshot,
        release_permit,
    ):
        with pytest.raises(
            SchedulerRunnerContractError,
            match="durable scheduler mutation permit",
        ):
            fixture.adapter.release_held(fixture.prepared, permit=release_permit)
    with pytest.raises(SchedulerRunnerContractError):
        fixture.adapter.query_held(
            fixture.prepared,
            SlurmJobRef(job_id=_JOB_ID, submission_marker="f" * 64),
        )
    with _submit_claim(fixture) as (_store, _snapshot, submit_permit):
        forged_marker = replace(
            submit_permit.state,
            _authority=preflight_module._STATE_AUTHORITY,
            submission_marker="e" * 64,
        )
        with pytest.raises(
            SchedulerRunnerContractError,
            match="durable scheduler mutation permit",
        ):
            fixture.adapter.submit_held(forged_marker, permit=submit_permit)
    assert started is False


def test_expired_and_reused_permits_fail_before_process_start(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    fixture.scenario(stdout_hex=_hex(f"{_JOB_ID}\n".encode("ascii")))
    real_popen = runner_module.subprocess.Popen
    starts = 0

    def counted_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal starts
        starts += 1
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(runner_module.subprocess, "Popen", counted_popen)

    with _submit_claim(fixture) as (_store, _snapshot, expired_permit):
        pass
    with pytest.raises(SchedulerRunnerContractError, match="durable scheduler mutation permit"):
        fixture.adapter.submit_held(expired_permit.state, permit=expired_permit)
    assert starts == 0

    with _submit_claim(fixture) as (_store, _snapshot, live_permit):
        fixture.adapter.submit_held(live_permit.state, permit=live_permit)
        with pytest.raises(
            SchedulerRunnerContractError,
            match="durable scheduler mutation permit",
        ):
            fixture.adapter.submit_held(live_permit.state, permit=live_permit)
    assert starts == 1


def test_manifest_paths_must_bind_componentwise_to_trusted_role_roots(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    manifest = fixture.prepared.manifest
    outside_worker = replace(
        manifest.worker,
        manifest_path="/outside/private/manifest.json",
    )
    outside_container = replace(
        manifest.containers[0],
        local_path="/outside/cache/fastqc.sif",
    )
    outside_execution_path = "/outside/raw/sample_R1.fastq.gz"
    outside_mapping = replace(
        manifest.path_mapping[0],
        execution_prefix="/outside/raw",
    )
    invalid_worker_state = prepare_preflight(replace(manifest, worker=outside_worker))
    with pytest.raises(SchedulerStateContractError, match="trusted compute installation"):
        SchedulerPreflightStore(fixture.config).create_or_load(
            invalid_worker_state,
            request_sha256=_request_sha256(invalid_worker_state),
        )

    invalid_manifests = (
        replace(manifest, work_dir="/outside/work/run-1"),
        replace(
            manifest,
            execution_paths=(outside_execution_path,),
            path_mapping=(outside_mapping,),
            input_set_hash=input_set_hash((outside_execution_path,)),
        ),
        replace(
            manifest,
            containers=(outside_container, *manifest.containers[1:]),
        ),
    )

    for invalid_manifest in invalid_manifests:
        invalid_state = prepare_preflight(invalid_manifest)
        with _submit_claim(fixture, invalid_state) as (  # noqa: SIM117
            _store,
            _snapshot,
            permit,
        ):
            with pytest.raises(
                SchedulerRunnerContractError,
                match="trusted scheduler role root",
            ):
                fixture.adapter.submit_held(permit.state, permit=permit)


def test_escaped_descendant_pipe_hold_has_bounded_cleanup(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    fixture.scenario(
        spawn_descendant=True,
        escape_descendant=True,
        descendant_sleep_seconds=1.0,
    )
    state = _polling(fixture.prepared)
    invocation = runner_module._make_invocation(
        fixture.config,
        operation="query_queue",
        argv=runner_module.build_squeue_argv(
            str(fixture.config.executables["squeue"].path),
            state.job,
        ),
        stdin_bytes=None,
        timeout_seconds=2.0,
        state=state,
    )
    started = runner_module.time.monotonic()
    descendant_pid: int | None = None
    try:
        result = runner_module._execute_invocation(fixture.config, invocation)
        elapsed = runner_module.time.monotonic() - started
        descendant_pid = int(fixture.record()["descendant_pid"])
    finally:
        if descendant_pid is not None:
            with suppress(ProcessLookupError):
                os.kill(descendant_pid, signal.SIGKILL)

    assert elapsed < 1.3
    assert result.transport_complete is False
    assert result.io_failed is True or result.timed_out is True
    assert "threading" not in inspect.getsource(runner_module)


@pytest.mark.parametrize("boundary", ["popen", "execute", "communicate", "parser"])
def test_mutation_interrupt_is_always_unknown_after_start_boundary(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    fixture = runner_fixture
    fixture.scenario(stdout_hex=_hex(f"{_JOB_ID}\n".encode("ascii")))

    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt

    if boundary == "popen":
        monkeypatch.setattr(runner_module.subprocess, "Popen", interrupted)
        expected_reason = "SCHEDULER_MUTATION_START_UNCERTAIN"
    elif boundary == "execute":
        monkeypatch.setattr(runner_module, "_execute_invocation", interrupted)
        expected_reason = "SCHEDULER_MUTATION_INTERRUPTED"
    elif boundary == "parser":
        monkeypatch.setattr(runner_module, "parse_sbatch_parsable_output", interrupted)
        expected_reason = "SCHEDULER_MUTATION_INTERRUPTED"
    else:
        monkeypatch.setattr(runner_module, "_communicate_bounded", interrupted)
        expected_reason = "SCHEDULER_MUTATION_INTERRUPTED"

    with _submit_claim(fixture) as (_store, _snapshot, permit):  # noqa: SIM117
        with pytest.raises(SchedulerMutationUnknown) as captured:
            fixture.adapter.submit_held(permit.state, permit=permit)

    assert captured.value.reason_code == expected_reason
    assert captured.value.io_failed is True
    if boundary == "parser":
        assert captured.value.stdin_bytes_written == len(permit.state.template_bytes)


def test_release_receipt_interrupt_preserves_mutation_unknown(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    fixture.scenario()

    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(runner_module, "SchedulerMutationReceipt", interrupted)

    with _release_claim(fixture) as (_store, _snapshot, permit):  # noqa: SIM117
        with pytest.raises(SchedulerMutationUnknown) as captured:
            fixture.adapter.release_held(permit.state, permit=permit)

    assert captured.value.reason_code == "SCHEDULER_MUTATION_INTERRUPTED"


@pytest.mark.parametrize(
    ("boundary", "failure", "expected_reason"),
    [
        ("popen", MemoryError, "SCHEDULER_MUTATION_START_UNCERTAIN"),
        ("parser", RuntimeError, "SCHEDULER_MUTATION_POST_TRANSPORT_FAILURE"),
        ("receipt", MemoryError, "SCHEDULER_MUTATION_POST_TRANSPORT_FAILURE"),
    ],
)
def test_unexpected_mutation_failure_is_never_exposed_as_retryable(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    failure: type[BaseException],
    expected_reason: str,
) -> None:
    fixture = runner_fixture
    fixture.scenario(stdout_hex=_hex(f"{_JOB_ID}\n".encode("ascii")))

    def failed(*_args: Any, **_kwargs: Any) -> Any:
        raise failure("synthetic mutation boundary failure")

    def submit_operation() -> object:
        with _submit_claim(fixture) as (_store, _snapshot, permit):
            return fixture.adapter.submit_held(permit.state, permit=permit)

    def release_operation() -> object:
        with _release_claim(fixture) as (_store, _snapshot, permit):
            return fixture.adapter.release_held(permit.state, permit=permit)

    if boundary == "popen":
        monkeypatch.setattr(runner_module.subprocess, "Popen", failed)
        operation = submit_operation
    elif boundary == "parser":
        monkeypatch.setattr(runner_module, "parse_sbatch_parsable_output", failed)
        operation = submit_operation
    else:
        fixture.scenario()
        monkeypatch.setattr(runner_module, "SchedulerMutationReceipt", failed)
        operation = release_operation

    with pytest.raises(SchedulerMutationUnknown) as captured:
        operation()

    assert captured.value.reason_code == expected_reason


def test_cleanup_failure_cannot_mask_post_start_mutation_unknown(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    fixture.scenario()

    def failed_transport(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("synthetic I/O failure")

    def failed_cleanup(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("synthetic cleanup failure")

    monkeypatch.setattr(runner_module, "_communicate_bounded", failed_transport)
    monkeypatch.setattr(runner_module, "_terminate_process_group", failed_cleanup)

    with _release_claim(fixture) as (_store, _snapshot, permit):  # noqa: SIM117
        with pytest.raises(SchedulerMutationUnknown) as captured:
            fixture.adapter.release_held(permit.state, permit=permit)

    assert captured.value.reason_code == "SCHEDULER_POST_START_IO_FAILURE"
    assert captured.value.io_failed is True


def test_terminal_state_keeps_read_only_scheduler_reconciliation(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    timed_out = record_scheduler_poll(
        _polling(fixture.prepared),
        queue=None,
        accounting=None,
        elapsed_seconds=61,
    )
    assert timed_out.phase == "timed_out"
    queue_row = f"{_JOB_ID}|{_SUBMITTED_AT}|{timed_out.submission_marker}|RUNNING\n"
    fixture.scenario(stdout_hex=_hex(queue_row.encode("ascii")))

    observation = fixture.adapter.query_queue(timed_out)

    assert observation is not None
    assert observation.state == "RUNNING"


def test_deadline_expiring_during_recheck_prevents_popen(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    state = _polling(fixture.prepared)
    invocation = runner_module._make_invocation(
        fixture.config,
        operation="query_queue",
        argv=runner_module.build_squeue_argv(
            str(fixture.config.executables["squeue"].path),
            state.job,
        ),
        stdin_bytes=None,
        timeout_seconds=0.05,
        state=state,
    )
    real_verify = runner_module.verify_scheduler_config_file
    started = False

    def slow_verify(config: TrustedSchedulerConfig) -> None:
        runner_module.time.sleep(0.08)
        real_verify(config)

    def unexpected_popen(*_args: Any, **_kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal started
        started = True
        raise AssertionError("Popen must not run after the absolute deadline")

    monkeypatch.setattr(runner_module, "verify_scheduler_config_file", slow_verify)
    monkeypatch.setattr(runner_module.subprocess, "Popen", unexpected_popen)

    with pytest.raises(
        SchedulerRunnerPreconditionError,
        match="prerequisites changed",
    ) as captured:
        runner_module._execute_invocation(fixture.config, invocation)

    assert captured.value.reason_code == "SCHEDULER_OPERATION_DEADLINE_EXPIRED"
    assert started is False


def test_process_exit_observed_after_absolute_deadline_is_not_success(
    runner_fixture: RunnerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = runner_fixture
    state = _polling(fixture.prepared)
    invocation = runner_module._make_invocation(
        fixture.config,
        operation="query_queue",
        argv=runner_module.build_squeue_argv(
            str(fixture.config.executables["squeue"].path),
            state.job,
        ),
        stdin_bytes=None,
        timeout_seconds=1.0,
        deadline=10.0,
        state=state,
    )
    process = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    process.wait(timeout=2)
    observed_times = iter((9.0, 11.0))
    monkeypatch.setattr(
        runner_module.time,
        "monotonic",
        lambda: next(observed_times, 11.0),
    )

    result = runner_module._communicate_bounded(
        process,
        invocation,
        runner_module._IOState(output_limit_bytes=1024),
    )

    assert result.return_code == 0
    assert result.timed_out is True
    assert result.transport_complete is False


def test_invocation_identity_binds_timeout_limits_environment_and_executable_hash(
    runner_fixture: RunnerFixture,
) -> None:
    fixture = runner_fixture
    state = _polling(fixture.prepared)
    argv = runner_module.build_squeue_argv(
        str(fixture.config.executables["squeue"].path),
        state.job,
    )
    first = runner_module._make_invocation(
        fixture.config,
        operation="query_queue",
        argv=argv,
        stdin_bytes=None,
        timeout_seconds=0.2,
        state=state,
    )
    second = runner_module._make_invocation(
        fixture.config,
        operation="query_queue",
        argv=argv,
        stdin_bytes=None,
        timeout_seconds=0.3,
        state=state,
    )

    assert first.invocation_sha256 != second.invocation_sha256
    source = inspect.getsource(runner_module._make_invocation)
    for binding in (
        "environment_sha256",
        "executable_sha256",
        "timeout_seconds",
        "output_limit_bytes",
        "config_sha256",
        "contract_sha256",
    ):
        assert binding in source
    assert "SchedulerCommandResult" not in runner_module.__all__


def test_v1_import_graph_does_not_load_scheduler_runner() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "import bioexec.main, bioexec.config, bioexec.protocol\n"
        "import bioexec.preflight, bioexec.deployment, bioexec.runner\n"
        "import bioexec.state, bioexec.commands\n"
        "assert 'bioexec.scheduler_runner' not in sys.modules\n"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr


def test_source_has_no_generic_shell_script_or_cancel_surface() -> None:
    source = inspect.getsource(runner_module)
    assert "shell=True" not in source
    assert "--wrap" not in source
    assert "scancel" not in source
    assert "os.environ" not in source
    assert "run(self" not in source
