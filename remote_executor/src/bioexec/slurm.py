"""Pure, dormant Slurm contract primitives for the first M7 design slice.

Nothing in the remote executor imports this module yet.  It deliberately does
not run scheduler commands, inspect the environment, read files, or expose a
cancel operation.  The functions below only validate policy, construct fixed
argument vectors, and parse bounded command output.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Literal

_SCHEDULER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", re.ASCII)
_JOB_ID = re.compile(r"[1-9][0-9]{0,9}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_STATE = re.compile(r"[A-Z][A-Z_]{0,31}", re.ASCII)
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}", re.ASCII)
_SUBMIT_TIME = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]",
    re.ASCII,
)
_CANCELLED_STATE = re.compile(r"CANCELLED by (?P<uid>0|[1-9][0-9]{0,9})", re.ASCII)
_TIME_LIMIT = re.compile(
    r"(?:(?P<days>[1-9][0-9]?)-)?"
    r"(?P<hours>[0-2][0-9]):(?P<minutes>[0-5][0-9]):(?P<seconds>[0-5][0-9])",
    re.ASCII,
)
_EXIT_CODE = re.compile(
    r"(?P<exit>0|[1-9][0-9]{0,2}):(?P<signal>0|[1-9][0-9]{0,2})",
    re.ASCII,
)
_SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]{1,4094}", re.ASCII)
_POLICY_FIELDS = frozenset(
    {
        "partition",
        "account",
        "qos",
        "time_limit",
        "cpus_per_task",
        "memory_mib",
        "submit_timeout_seconds",
        "status_poll_seconds",
        "max_pending_seconds",
    }
)
_MAX_JOB_ID = 4_294_967_295
_MAX_TIME_LIMIT_SECONDS = 30 * 24 * 60 * 60
_MAX_CPUS_PER_TASK = 1_024
_MAX_MEMORY_MIB = 16 * 1024 * 1024
_MAX_SUBMIT_OUTPUT_BYTES = 256
_MAX_STATUS_OUTPUT_BYTES = 16 * 1024

_QUEUED_STATES = frozenset(
    {
        "PENDING",
        "CONFIGURING",
        "EXPEDITING",
        "POWER_UP_NODE",
        "RESV_DEL_HOLD",
    }
)
_RESTART_STATES = frozenset({"REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SPECIAL_EXIT"})
_ACTIVE_STATES = frozenset(
    {
        "RUNNING",
        "SUSPENDED",
        "COMPLETING",
        "SIGNALING",
        "STAGE_OUT",
        "STOPPED",
        "RESIZING",
        "UPDATE_DB",
    }
)
_FAILED_STATES = frozenset(
    {
        "BOOT_FAIL",
        "CANCELLED",
        "DEADLINE",
        "FAILED",
        "NODE_FAIL",
        "OUT_OF_MEMORY",
        "PREEMPTED",
        "TIMEOUT",
        "LAUNCH_FAILED",
        "RECONFIG_FAIL",
        "REVOKED",
    }
)

MappedState = Literal["queued", "active", "succeeded", "failed", "indeterminate"]
ObservationSource = Literal["squeue", "sacct"]


class SlurmContractError(ValueError):
    """A scheduler value or observation violates the fixed M7 contract."""


@dataclass(frozen=True)
class SlurmSchedulerPolicy:
    """Strict site policy from which no free scheduler flags can be derived."""

    partition: str
    account: str | None
    qos: str | None
    time_limit: str
    cpus_per_task: int
    memory_mib: int
    submit_timeout_seconds: int
    status_poll_seconds: int
    max_pending_seconds: int

    def __post_init__(self) -> None:
        _scheduler_name(self.partition, "partition")
        _optional_scheduler_name(self.account, "account")
        _optional_scheduler_name(self.qos, "qos")
        _canonical_time_limit(self.time_limit)
        _bounded_int(self.cpus_per_task, "cpus_per_task", 1, _MAX_CPUS_PER_TASK)
        _bounded_int(self.memory_mib, "memory_mib", 1_024, _MAX_MEMORY_MIB)
        _bounded_int(self.submit_timeout_seconds, "submit_timeout_seconds", 1, 300)
        _bounded_int(self.status_poll_seconds, "status_poll_seconds", 5, 3_600)
        _bounded_int(self.max_pending_seconds, "max_pending_seconds", 60, 2_592_000)
        if self.status_poll_seconds > self.max_pending_seconds:
            raise SlurmContractError("status_poll_seconds must not exceed max_pending_seconds")

    @classmethod
    def from_mapping(cls, value: Any) -> SlurmSchedulerPolicy:
        """Parse an exact-key policy mapping and reject every extension field."""

        if not isinstance(value, dict) or set(value) != _POLICY_FIELDS:
            raise SlurmContractError("scheduler policy fields do not match the contract")
        return cls(
            partition=_require_string(value["partition"], "partition"),
            account=_require_optional_string(value["account"], "account"),
            qos=_require_optional_string(value["qos"], "qos"),
            time_limit=_require_string(value["time_limit"], "time_limit"),
            cpus_per_task=_require_int(value["cpus_per_task"], "cpus_per_task"),
            memory_mib=_require_int(value["memory_mib"], "memory_mib"),
            submit_timeout_seconds=_require_int(
                value["submit_timeout_seconds"], "submit_timeout_seconds"
            ),
            status_poll_seconds=_require_int(value["status_poll_seconds"], "status_poll_seconds"),
            max_pending_seconds=_require_int(value["max_pending_seconds"], "max_pending_seconds"),
        )

    def as_mapping(self) -> dict[str, str | int | None]:
        """Return the canonical, hashable-field ordering used by later contracts."""

        return {
            "partition": self.partition,
            "account": self.account,
            "qos": self.qos,
            "time_limit": self.time_limit,
            "cpus_per_task": self.cpus_per_task,
            "memory_mib": self.memory_mib,
            "submit_timeout_seconds": self.submit_timeout_seconds,
            "status_poll_seconds": self.status_poll_seconds,
            "max_pending_seconds": self.max_pending_seconds,
        }


def canonical_scheduler_policy_bytes(policy: SlurmSchedulerPolicy) -> bytes:
    """Serialize one validated scheduler policy for cross-contract hashing."""

    if not isinstance(policy, SlurmSchedulerPolicy):
        raise SlurmContractError("policy must be a validated SlurmSchedulerPolicy")
    return json.dumps(
        policy.as_mapping(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def scheduler_policy_hash(policy: SlurmSchedulerPolicy) -> str:
    """Return the lowercase SHA-256 identity shared by profile/config/protocol v2."""

    return hashlib.sha256(canonical_scheduler_policy_bytes(policy)).hexdigest()


@dataclass(frozen=True)
class SlurmSubmitSpec:
    """Hash-bound values needed to construct one held allocation request."""

    policy: SlurmSchedulerPolicy
    submission_marker: str
    working_directory: str
    log_directory: str

    def __post_init__(self) -> None:
        if not isinstance(self.policy, SlurmSchedulerPolicy):
            raise SlurmContractError("policy must be a validated SlurmSchedulerPolicy")
        _submission_marker(self.submission_marker)
        _absolute_path(self.working_directory, "working_directory")
        _absolute_path(self.log_directory, "log_directory")


@dataclass(frozen=True)
class SlurmJobRef:
    """One marker-bound allocation ID, optionally bound to its submit time."""

    job_id: str
    submission_marker: str
    submitted_at: str | None = None

    def __post_init__(self) -> None:
        _job_id(self.job_id)
        _submission_marker(self.submission_marker)
        if self.submitted_at is not None:
            _submit_time(self.submitted_at)


@dataclass(frozen=True)
class SlurmHeldJob:
    """Exact ``squeue`` evidence that one bound job has a user hold."""

    job: SlurmJobRef
    state: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.job, SlurmJobRef):
            raise SlurmContractError("held job must contain a validated SlurmJobRef")
        if self.job.submitted_at is None:
            raise SlurmContractError("held job must bind the scheduler submit time")
        if self.state != "PENDING":
            raise SlurmContractError("held job state must be exactly PENDING")
        if self.reason != "JobHeldUser":
            raise SlurmContractError("held job reason must be exactly JobHeldUser")


@dataclass(frozen=True)
class SlurmObservation:
    """One bounded scheduler row for the exact submitted allocation."""

    source: ObservationSource
    job: SlurmJobRef
    state: str
    exit_code: tuple[int, int] | None = None
    cancelled_by_uid: int | None = None

    def __post_init__(self) -> None:
        if self.source not in {"squeue", "sacct"}:
            raise SlurmContractError("observation source is not supported")
        if not isinstance(self.job, SlurmJobRef):
            raise SlurmContractError("observation job must be a SlurmJobRef")
        if self.job.submitted_at is None:
            raise SlurmContractError("observation job must bind the scheduler submit time")
        if not isinstance(self.state, str) or not _STATE.fullmatch(self.state):
            raise SlurmContractError("Slurm state must be one canonical extended token")
        if self.source == "squeue" and self.exit_code is not None:
            raise SlurmContractError("squeue observations cannot include an exit code")
        if self.exit_code is not None:
            _validate_exit_code(self.exit_code)
        if self.cancelled_by_uid is not None:
            _bounded_int(self.cancelled_by_uid, "cancelled_by_uid", 0, _MAX_JOB_ID)
            if self.source != "sacct" or self.state != "CANCELLED":
                raise SlurmContractError(
                    "a cancellation UID is valid only on a sacct CANCELLED observation"
                )


@dataclass(frozen=True)
class SlurmMappedState:
    """Fail-closed scheduler state ready for a future lifecycle adapter."""

    state: MappedState
    code: str

    def __post_init__(self) -> None:
        if self.state not in {"queued", "active", "succeeded", "failed", "indeterminate"}:
            raise SlurmContractError("mapped state is not supported")
        if not isinstance(self.code, str) or not _CODE.fullmatch(self.code):
            raise SlurmContractError("mapped state code must be a safe stable identifier")


def build_sbatch_argv(binary: str, spec: SlurmSubmitSpec) -> tuple[str, ...]:
    """Construct the only admitted held ``sbatch`` argument vector.

    There is intentionally no script path or ``--wrap`` argument.  A later
    activation slice must provide reviewed, hash-bound script bytes on stdin,
    durably bind the returned job ID, and only then release the held job.
    """

    executable = _scheduler_binary(binary, "sbatch")
    if not isinstance(spec, SlurmSubmitSpec):
        raise SlurmContractError("spec must be a validated SlurmSubmitSpec")
    policy = spec.policy
    arguments = [
        executable,
        "--parsable",
        "--hold",
        "--export=NIL",
        "--no-requeue",
        "--nodes=1",
        "--ntasks=1",
        f"--cpus-per-task={policy.cpus_per_task}",
        f"--mem={policy.memory_mib}M",
        f"--partition={policy.partition}",
    ]
    if policy.account is not None:
        arguments.append(f"--account={policy.account}")
    if policy.qos is not None:
        arguments.append(f"--qos={policy.qos}")
    arguments.extend(
        (
            f"--time={policy.time_limit}",
            f"--job-name={spec.submission_marker}",
            f"--chdir={spec.working_directory}",
            f"--output={spec.log_directory}/slurm-%j.stdout.log",
            f"--error={spec.log_directory}/slurm-%j.stderr.log",
        )
    )
    return tuple(arguments)


def build_squeue_argv(binary: str, job: SlurmJobRef) -> tuple[str, ...]:
    """Construct one exact, non-iterating ``squeue`` state query."""

    executable = _scheduler_binary(binary, "squeue")
    if not isinstance(job, SlurmJobRef):
        raise SlurmContractError("job must be a validated SlurmJobRef")
    return (
        executable,
        "--local",
        "--noheader",
        f"--jobs={job.job_id}",
        "--states=all",
        "--format=%i|%V|%j|%T",
    )


def build_sacct_argv(binary: str, job: SlurmJobRef) -> tuple[str, ...]:
    """Construct one exact allocation-only ``sacct`` reconciliation query."""

    executable = _scheduler_binary(binary, "sacct")
    if not isinstance(job, SlurmJobRef):
        raise SlurmContractError("job must be a validated SlurmJobRef")
    return (
        executable,
        "--local",
        "--noheader",
        "--parsable2",
        "--allocations",
        "--duplicates",
        f"--jobs={job.job_id}",
        "--format=JobIDRaw,Submit,JobName%64,State%64,ExitCode",
    )


def build_squeue_hold_argv(binary: str, job: SlurmJobRef) -> tuple[str, ...]:
    """Construct the only query admitted to prove an exact user-held job."""

    executable = _scheduler_binary(binary, "squeue")
    if not isinstance(job, SlurmJobRef):
        raise SlurmContractError("job must be a validated SlurmJobRef")
    return (
        executable,
        "--local",
        "--noheader",
        f"--jobs={_job_id(job.job_id)}",
        "--states=PENDING",
        "--format=%i|%V|%j|%T|%r",
    )


def build_scontrol_release_argv(binary: str, held_job: SlurmHeldJob) -> tuple[str, ...]:
    """Construct the only admitted held-job release argument vector."""

    executable = _scheduler_binary(binary, "scontrol")
    if not isinstance(held_job, SlurmHeldJob):
        raise SlurmContractError("release requires validated user-held job evidence")
    evidence = SlurmHeldJob(
        job=held_job.job,
        state=held_job.state,
        reason=held_job.reason,
    )
    return (executable, "release", _job_id(evidence.job.job_id))


def build_squeue_discovery_argv(binary: str, submission_marker: str) -> tuple[str, ...]:
    """Construct a positive-only lookup for a held job after response loss."""

    executable = _scheduler_binary(binary, "squeue")
    marker = _submission_marker(submission_marker)
    return (
        executable,
        "--local",
        "--noheader",
        "--me",
        f"--name={marker}",
        "--format=%i|%V|%j|%T",
    )


def build_scheduler_environment(private_home: str) -> Mapping[str, str]:
    """Create a minimal immutable environment without consulting ``os.environ``."""

    home = _absolute_path(private_home, "private_home")
    return MappingProxyType({"HOME": home, "LANG": "C", "LC_ALL": "C"})


def parse_sbatch_parsable_output(data: bytes, submission_marker: str) -> SlurmJobRef:
    """Parse one local-cluster ``sbatch --parsable`` response."""

    marker = _submission_marker(submission_marker)
    lines = _decode_rows(data, _MAX_SUBMIT_OUTPUT_BYTES, allow_empty=False)
    if len(lines) != 1:
        raise SlurmContractError("sbatch output must contain exactly one row")
    if ";" in lines[0]:
        raise SlurmContractError("cluster-qualified sbatch output is not supported")
    return SlurmJobRef(job_id=lines[0], submission_marker=marker)


def parse_squeue_output(data: bytes, expected_job: SlurmJobRef) -> SlurmObservation | None:
    """Parse zero or one exact ``squeue`` row.

    ``None`` means only that this query returned no row.  It never means that a
    job does not exist and must not authorize another submission.
    """

    if not isinstance(expected_job, SlurmJobRef):
        raise SlurmContractError("expected_job must be a validated SlurmJobRef")
    rows = _decode_rows(data, _MAX_STATUS_OUTPUT_BYTES, allow_empty=True)
    if not rows:
        return None
    if len(rows) != 1:
        raise SlurmContractError("squeue output is ambiguous")
    fields = _status_fields(rows[0], expected=4)
    job_id = _padded_field(fields[0], "squeue job ID")
    submitted_at = _padded_field(fields[1], "squeue submit time")
    marker = _padded_field(fields[2], "squeue job name")
    raw_state = _padded_field(fields[3], "squeue state")
    if job_id != expected_job.job_id:
        raise SlurmContractError("squeue returned a different or composite job ID")
    job = _observed_job(expected_job, job_id, marker, submitted_at, source="squeue")
    state, cancelled_by_uid = _state_field(raw_state)
    if cancelled_by_uid is not None:
        raise SlurmContractError("squeue must not report an accounting cancellation suffix")
    return SlurmObservation(source="squeue", job=job, state=state)


def parse_squeue_hold_output(data: bytes, expected_job: SlurmJobRef) -> SlurmHeldJob | None:
    """Parse zero or one exact user-hold row for the expected job.

    ``None`` means only that this query did not prove a held job.  Any returned
    value binds the exact job ID, marker, scheduler submit time, pending state,
    and the user-hold reason required before release.
    """

    if not isinstance(expected_job, SlurmJobRef):
        raise SlurmContractError("expected_job must be a validated SlurmJobRef")
    rows = _decode_rows(data, _MAX_STATUS_OUTPUT_BYTES, allow_empty=True)
    if not rows:
        return None
    if len(rows) != 1:
        raise SlurmContractError("squeue hold output is ambiguous")
    fields = _status_fields(rows[0], expected=5)
    job_id = _padded_field(fields[0], "squeue hold job ID")
    submitted_at = _padded_field(fields[1], "squeue hold submit time")
    marker = _padded_field(fields[2], "squeue hold job name")
    state = _padded_field(fields[3], "squeue hold state")
    reason = _padded_field(fields[4], "squeue hold reason")
    if job_id != expected_job.job_id:
        raise SlurmContractError("squeue hold returned a different or composite job ID")
    job = _observed_job(expected_job, job_id, marker, submitted_at, source="squeue hold")
    return SlurmHeldJob(job=job, state=state, reason=reason)


def parse_sacct_output(data: bytes, expected_job: SlurmJobRef) -> SlurmObservation | None:
    """Parse at most one allocation-only ``sacct --parsable2`` row."""

    if not isinstance(expected_job, SlurmJobRef):
        raise SlurmContractError("expected_job must be a validated SlurmJobRef")
    rows = _decode_rows(data, _MAX_STATUS_OUTPUT_BYTES, allow_empty=True)
    if not rows:
        return None
    if len(rows) != 1:
        raise SlurmContractError("sacct output has duplicate or composite allocation rows")
    fields = _status_fields(rows[0], expected=5)
    job_id = _padded_field(fields[0], "sacct job ID")
    submitted_at = _padded_field(fields[1], "sacct submit time")
    marker = _padded_field(fields[2], "sacct job name")
    raw_state = _padded_field(fields[3], "sacct state")
    raw_exit = _padded_field(fields[4], "sacct exit code", allow_empty=True)
    if job_id != expected_job.job_id:
        raise SlurmContractError("sacct returned a different, step, array, or heterogeneous ID")
    job = _observed_job(expected_job, job_id, marker, submitted_at, source="sacct")
    state, cancelled_by_uid = _state_field(raw_state)
    exit_code = None if not raw_exit else _parse_exit_code(raw_exit)
    return SlurmObservation(
        source="sacct",
        job=job,
        state=state,
        exit_code=exit_code,
        cancelled_by_uid=cancelled_by_uid,
    )


def parse_squeue_discovery_output(data: bytes, submission_marker: str) -> SlurmObservation | None:
    """Resolve zero or one marker-bound held job after a lost response.

    Zero matches remain unknown and multiple matches are a conflict.  Neither
    result authorizes another ``sbatch`` call.
    """

    marker = _submission_marker(submission_marker)
    rows = _decode_rows(data, _MAX_STATUS_OUTPUT_BYTES, allow_empty=True)
    if not rows:
        return None
    if len(rows) != 1:
        raise SlurmContractError("submission discovery returned multiple jobs")
    fields = _status_fields(rows[0], expected=4)
    job_id = _padded_field(fields[0], "discovered job ID")
    submitted_at = _padded_field(fields[1], "discovered submit time")
    observed_marker = _padded_field(fields[2], "discovered job name")
    raw_state = _padded_field(fields[3], "discovered state")
    provisional = SlurmJobRef(job_id=job_id, submission_marker=marker)
    job = _observed_job(
        provisional,
        job_id,
        observed_marker,
        submitted_at,
        source="submission discovery",
    )
    state, cancelled_by_uid = _state_field(raw_state)
    if cancelled_by_uid is not None:
        raise SlurmContractError("squeue must not report an accounting cancellation suffix")
    return SlurmObservation(source="squeue", job=job, state=state)


def map_slurm_observation(observation: SlurmObservation) -> SlurmMappedState:
    """Map one exact scheduler observation without guessing through ambiguity."""

    if not isinstance(observation, SlurmObservation):
        raise SlurmContractError("observation must be a validated SlurmObservation")
    state = observation.state
    if state in _QUEUED_STATES:
        return SlurmMappedState(state="queued", code=f"SLURM_{state}")
    if state in _ACTIVE_STATES:
        return SlurmMappedState(state="active", code=f"SLURM_{state}")
    if state in _RESTART_STATES:
        return SlurmMappedState(state="indeterminate", code="SLURM_RESTART_REQUIRES_RECONCILIATION")
    if state != "COMPLETED" and state not in _FAILED_STATES:
        return SlurmMappedState(state="indeterminate", code="SLURM_STATE_UNKNOWN")
    if observation.source != "sacct":
        return SlurmMappedState(state="indeterminate", code="SLURM_TERMINAL_REQUIRES_SACCT")
    if observation.exit_code is None:
        return SlurmMappedState(state="indeterminate", code="SLURM_EXIT_CODE_UNAVAILABLE")
    if state == "COMPLETED":
        if observation.exit_code == (0, 0):
            return SlurmMappedState(state="succeeded", code="SLURM_COMPLETED")
        return SlurmMappedState(state="indeterminate", code="SLURM_SUCCESS_EXIT_CONFLICT")
    if observation.exit_code == (0, 0):
        return SlurmMappedState(state="indeterminate", code="SLURM_FAILURE_EXIT_CONFLICT")
    return SlurmMappedState(state="failed", code=f"SLURM_{state}")


def reconcile_slurm_observations(
    queue: SlurmObservation | None,
    accounting: SlurmObservation | None,
    previous: SlurmMappedState | None = None,
) -> SlurmMappedState:
    """Reconcile queue/accounting evidence without state regression or guessing."""

    for observation in (queue, accounting):
        if observation is not None and not isinstance(observation, SlurmObservation):
            raise SlurmContractError("reconciliation inputs must be Slurm observations")
    if previous is not None and not isinstance(previous, SlurmMappedState):
        raise SlurmContractError("previous must be a SlurmMappedState")
    if queue is not None and queue.source != "squeue":
        raise SlurmContractError("queue evidence must come from squeue")
    if accounting is not None and accounting.source != "sacct":
        raise SlurmContractError("accounting evidence must come from sacct")

    current = [
        map_slurm_observation(observation)
        for observation in (queue, accounting)
        if observation is not None
    ]
    if previous is not None and previous.state in {"succeeded", "failed"}:
        if not current or all(value == previous for value in current):
            return previous
        return SlurmMappedState(state="indeterminate", code="SLURM_TERMINAL_STATE_REGRESSION")
    if not current:
        return SlurmMappedState(state="indeterminate", code="SLURM_OBSERVATION_MISSING")
    if (
        queue is not None
        and accounting is not None
        and (queue.job != accounting.job or current[0] != current[1])
    ):
        return SlurmMappedState(state="indeterminate", code="SLURM_OBSERVATION_CONFLICT")
    return current[-1]


def _scheduler_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SCHEDULER_NAME.fullmatch(value):
        raise SlurmContractError(f"{label} must be one bounded ASCII scheduler identifier")
    return value


def _submission_marker(value: Any) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value) or value == "0" * 64:
        raise SlurmContractError("submission_marker must be one non-placeholder lowercase SHA-256")
    return value


def _submit_time(value: Any) -> str:
    if not isinstance(value, str) or not _SUBMIT_TIME.fullmatch(value):
        raise SlurmContractError("submit time must use canonical YYYY-MM-DDTHH:MM:SS form")
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise SlurmContractError("submit time is not a real calendar timestamp") from exc
    return value


def _state_field(value: str) -> tuple[str, int | None]:
    if _STATE.fullmatch(value):
        return value, None
    cancelled = _CANCELLED_STATE.fullmatch(value)
    if cancelled is None:
        raise SlurmContractError("Slurm state is malformed or truncated")
    uid = int(cancelled.group("uid"))
    _bounded_int(uid, "cancelled_by_uid", 0, _MAX_JOB_ID)
    return "CANCELLED", uid


def _observed_job(
    expected: SlurmJobRef,
    job_id: str,
    marker: str,
    submitted_at: str,
    *,
    source: str,
) -> SlurmJobRef:
    if job_id != expected.job_id:
        raise SlurmContractError(f"{source} returned a different or composite job ID")
    if marker != expected.submission_marker:
        raise SlurmContractError(f"{source} returned a different submission marker")
    _submit_time(submitted_at)
    if expected.submitted_at is not None and submitted_at != expected.submitted_at:
        raise SlurmContractError(f"{source} returned a different submission attempt")
    return SlurmJobRef(
        job_id=job_id,
        submission_marker=marker,
        submitted_at=submitted_at,
    )


def _optional_scheduler_name(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _scheduler_name(value, label)


def _canonical_time_limit(value: Any) -> str:
    if not isinstance(value, str):
        raise SlurmContractError("time_limit must be a canonical string")
    match = _TIME_LIMIT.fullmatch(value)
    if match is None:
        raise SlurmContractError("time_limit must use canonical [D-]HH:MM:SS form")
    days = int(match.group("days") or "0")
    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    seconds = int(match.group("seconds"))
    total = (((days * 24) + hours) * 60 + minutes) * 60 + seconds
    if hours > 23 or not 1 <= total <= _MAX_TIME_LIMIT_SECONDS:
        raise SlurmContractError("time_limit is outside the supported range")
    return value


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SlurmContractError(f"{label} is outside its strict integer range")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise SlurmContractError(f"{label} must be a string")
    return value


def _require_optional_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, label)


def _require_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise SlurmContractError(f"{label} must be a strict integer")
    return value


def _absolute_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_PATH.fullmatch(value):
        raise SlurmContractError(f"{label} must be one bounded safe absolute POSIX path")
    path = PurePosixPath(value)
    if path == PurePosixPath("/") or ".." in path.parts or str(path) != value:
        raise SlurmContractError(f"{label} must be a canonical non-root POSIX path")
    return value


def _scheduler_binary(value: Any, expected_name: str) -> str:
    binary = _absolute_path(value, f"{expected_name} binary")
    if PurePosixPath(binary).name != expected_name:
        raise SlurmContractError(f"scheduler binary must be the reviewed {expected_name} leaf")
    return binary


def _job_id(value: Any) -> str:
    if not isinstance(value, str) or not _JOB_ID.fullmatch(value):
        raise SlurmContractError("job ID must be one canonical positive ASCII decimal")
    if int(value) > _MAX_JOB_ID:
        raise SlurmContractError("job ID exceeds the supported Slurm range")
    return value


def _decode_rows(data: Any, limit: int, *, allow_empty: bool) -> list[str]:
    if not isinstance(data, bytes) or len(data) > limit:
        raise SlurmContractError("scheduler output must be bounded bytes")
    if not data:
        if allow_empty:
            return []
        raise SlurmContractError("scheduler output must not be empty")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SlurmContractError("scheduler output must be canonical ASCII") from exc
    if text.endswith("\n"):
        text = text[:-1]
    if not text or "\r" in text or "\x00" in text:
        raise SlurmContractError("scheduler output framing is invalid")
    rows = text.split("\n")
    if any(not row for row in rows):
        raise SlurmContractError("scheduler output contains an empty or extra row")
    return rows


def _status_fields(row: str, *, expected: int) -> list[str]:
    fields = row.split("|")
    if len(fields) != expected:
        raise SlurmContractError("scheduler status row has unexpected fields")
    return fields


def _padded_field(raw: str, label: str, *, allow_empty: bool = False) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise SlurmContractError(f"{label} contains a control character")
    value = raw.strip(" ")
    if not value and not allow_empty:
        raise SlurmContractError(f"{label} must not be empty")
    return value


def _parse_exit_code(value: str) -> tuple[int, int]:
    match = _EXIT_CODE.fullmatch(value)
    if match is None:
        raise SlurmContractError("exit code must use canonical exit:signal form")
    result = (int(match.group("exit")), int(match.group("signal")))
    _validate_exit_code(result)
    return result


def _validate_exit_code(value: Any) -> tuple[int, int]:
    if (
        not isinstance(value, tuple)
        or len(value) != 2
        or any(type(part) is not int or not 0 <= part <= 255 for part in value)
    ):
        raise SlurmContractError("exit code must contain bounded strict exit and signal values")
    return value


__all__ = [
    "SlurmContractError",
    "SlurmHeldJob",
    "SlurmJobRef",
    "SlurmMappedState",
    "SlurmObservation",
    "SlurmSchedulerPolicy",
    "SlurmSubmitSpec",
    "build_sacct_argv",
    "build_sbatch_argv",
    "build_scheduler_environment",
    "build_scontrol_release_argv",
    "build_squeue_argv",
    "build_squeue_discovery_argv",
    "build_squeue_hold_argv",
    "canonical_scheduler_policy_bytes",
    "map_slurm_observation",
    "parse_sacct_output",
    "parse_sbatch_parsable_output",
    "parse_squeue_discovery_output",
    "parse_squeue_hold_output",
    "parse_squeue_output",
    "reconcile_slurm_observations",
    "scheduler_policy_hash",
]
