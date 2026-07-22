"""Dormant, fixed-operation process adapter for M7 Slurm commands.

This module is deliberately separate from the reachable version-1 command
runner.  It exposes no generic command method: callers can only submit the
exact held compute-preflight template, inspect that attempt through fixed
``squeue``/``sacct`` queries, or release the exact validated held job.

Every operation rechecks the trusted config file, private state root, and the
one executable binding immediately before ``Popen``.  The recheck and process
creation remain two pathname operations, so this slice does not claim to
eliminate a hostile same-account race between them.  Activation must either
exclude same-account mutation of the reviewed installation or replace this
boundary with an exact descriptor-backed execution design.

Nothing imports this module from the installed service.  It performs no
scheduler operation unless a future caller explicitly constructs the adapter
with a trusted version-2 configuration and invokes one of its six methods.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import IO, Literal, TypeVar

from .scheduler_config_loader import (
    RootRole,
    SchedulerConfigLoadError,
    TrustedDirectoryBinding,
    TrustedSchedulerConfig,
    verify_scheduler_config_file,
    verify_scheduler_executable,
    verify_scheduler_root,
)
from .scheduler_preflight import (
    SchedulerPreflightError,
    SchedulerPreflightState,
    prepare_preflight,
    render_compute_template,
)
from .scheduler_state import (
    SchedulerMutationPermit,
    SchedulerMutationPermitError,
    _consume_mutation_permit,
)
from .slurm import (
    SlurmContractError,
    SlurmHeldJob,
    SlurmJobRef,
    SlurmObservation,
    SlurmSubmitSpec,
    build_sacct_argv,
    build_sbatch_argv,
    build_scheduler_environment,
    build_scontrol_release_argv,
    build_squeue_argv,
    build_squeue_discovery_argv,
    build_squeue_hold_argv,
    parse_sacct_output,
    parse_sbatch_parsable_output,
    parse_squeue_discovery_output,
    parse_squeue_hold_output,
    parse_squeue_output,
)

SchedulerOperation = Literal[
    "submit_held",
    "query_held",
    "discover_submit",
    "release_held",
    "query_queue",
    "query_accounting",
]
SchedulerExecutableRole = Literal["sbatch", "squeue", "sacct", "scontrol"]

_MUTATION_OPERATIONS = frozenset({"submit_held", "release_held"})
_JOB_QUERY_PHASES = frozenset(
    {
        "held",
        "release_ready",
        "release_unknown",
        "polling",
        "awaiting_evidence",
        "candidate",
        "passed",
        "failed",
        "indeterminate",
        "timed_out",
    }
)
_OPERATION_ROLES: Mapping[SchedulerOperation, SchedulerExecutableRole] = MappingProxyType(
    {
        "submit_held": "sbatch",
        "query_held": "squeue",
        "discover_submit": "squeue",
        "release_held": "scontrol",
        "query_queue": "squeue",
        "query_accounting": "sacct",
    }
)
_CHUNK_BYTES = 64 * 1024
_POLL_SECONDS = 0.02
_PROCESS_EXIT_DRAIN_SECONDS = 0.50
_CLEANUP_BUDGET_SECONDS = 0.25
_TERM_GRACE_SECONDS = 0.05


class SchedulerRunnerContractError(ValueError):
    """A caller attempted an operation outside the fixed scheduler contract."""


class SchedulerRunnerPreconditionError(RuntimeError):
    """A trusted filesystem binding failed before process creation."""

    def __init__(
        self,
        operation: SchedulerOperation,
        invocation_sha256: str,
        reason_code: str = "SCHEDULER_TRUSTED_PREREQUISITE_CHANGED",
    ) -> None:
        self.operation = operation
        self.invocation_sha256 = invocation_sha256
        self.reason_code = reason_code
        super().__init__("trusted scheduler command prerequisites changed before execution")


class SchedulerCommandStartError(RuntimeError):
    """The reviewed scheduler executable was not successfully started."""

    def __init__(self, operation: SchedulerOperation, invocation_sha256: str) -> None:
        self.operation = operation
        self.invocation_sha256 = invocation_sha256
        super().__init__("the reviewed scheduler command could not be started")


class SchedulerMutationUnknown(RuntimeError):
    """A submit/release may have started and its mutation outcome is ambiguous."""

    def __init__(
        self,
        *,
        operation: SchedulerOperation,
        invocation_sha256: str,
        reason_code: str,
        return_code: int | None,
        timed_out: bool,
        output_limit_exceeded: bool,
        io_failed: bool,
        stdin_sha256: str | None,
        stdin_size: int,
        stdin_bytes_written: int,
    ) -> None:
        self.operation = operation
        self.invocation_sha256 = invocation_sha256
        self.reason_code = reason_code
        self.return_code = return_code
        self.timed_out = timed_out
        self.output_limit_exceeded = output_limit_exceeded
        self.io_failed = io_failed
        self.stdin_sha256 = stdin_sha256
        self.stdin_size = stdin_size
        self.stdin_bytes_written = stdin_bytes_written
        super().__init__("the scheduler mutation outcome is unknown and must not be replayed")


class SchedulerQueryRetryableError(RuntimeError):
    """A read-only scheduler query lacked one complete trustworthy response."""

    def __init__(
        self,
        *,
        operation: SchedulerOperation,
        invocation_sha256: str,
        reason_code: str,
    ) -> None:
        self.operation = operation
        self.invocation_sha256 = invocation_sha256
        self.reason_code = reason_code
        super().__init__(
            "the scheduler query did not return complete trustworthy transport evidence"
        )


class SchedulerQueryEvidenceError(RuntimeError):
    """A completed query returned bytes outside the strict Slurm grammar."""

    def __init__(self, operation: SchedulerOperation, invocation_sha256: str) -> None:
        self.operation = operation
        self.invocation_sha256 = invocation_sha256
        super().__init__("the scheduler query returned invalid or conflicting evidence")


@dataclass(frozen=True)
class SchedulerMutationReceipt:
    """Sanitized success evidence for the one non-output release operation."""

    operation: Literal["release_held"]
    invocation_sha256: str


@dataclass(frozen=True)
class SchedulerCommandResult:
    """Internal raw-byte transport result; it never contains stdin or environment."""

    operation: SchedulerOperation
    invocation_sha256: str
    argv: tuple[str, ...]
    return_code: int | None
    stdout: bytes
    stderr: bytes
    stdin_sha256: str | None
    stdin_size: int
    stdin_bytes_written: int
    timed_out: bool = False
    output_limit_exceeded: bool = False
    io_failed: bool = False

    @property
    def transport_complete(self) -> bool:
        """Whether all local transport evidence completed without truncation."""

        return (
            not self.timed_out
            and not self.output_limit_exceeded
            and not self.io_failed
            and self.return_code is not None
            and self.stdin_bytes_written == self.stdin_size
        )


@dataclass(frozen=True)
class _Invocation:
    operation: SchedulerOperation
    role: SchedulerExecutableRole
    argv: tuple[str, ...]
    stdin_bytes: bytes | None
    stdin_sha256: str | None
    stdin_size: int
    cwd: Path
    environment: Mapping[str, str]
    timeout_seconds: float
    deadline: float
    output_limit_bytes: int
    invocation_sha256: str
    root_checks: tuple[tuple[RootRole, int], ...]


@dataclass
class _IOState:
    output_limit_bytes: int
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    total_output_bytes: int = 0
    stdin_bytes_written: int = 0
    overflow: bool = False
    io_failed: bool = False

    def consume(self, stream: Literal["stdout", "stderr"], chunk: bytes) -> None:
        remaining = max(0, self.output_limit_bytes - self.total_output_bytes)
        accepted = chunk[:remaining]
        target = self.stdout if stream == "stdout" else self.stderr
        target.extend(accepted)
        self.total_output_bytes += len(accepted)
        if len(accepted) != len(chunk):
            self.overflow = True

    def record_stdin_write(self, amount: int) -> None:
        self.stdin_bytes_written += amount

    def snapshot(self) -> tuple[bytes, bytes, int]:
        return bytes(self.stdout), bytes(self.stderr), self.stdin_bytes_written


@dataclass(frozen=True)
class _SelectorTarget:
    pipe: IO[bytes]
    direction: Literal["read", "write"]
    stream: Literal["stdout", "stderr"] | None = None


class _PostStartFailure(RuntimeError):
    def __init__(
        self,
        operation: SchedulerOperation,
        invocation_sha256: str,
        *,
        return_code: int | None,
        stdin_bytes_written: int,
        reason_code: str = "SCHEDULER_POST_START_IO_FAILURE",
    ) -> None:
        self.operation = operation
        self.invocation_sha256 = invocation_sha256
        self.return_code = return_code
        self.stdin_bytes_written = stdin_bytes_written
        self.reason_code = reason_code
        super().__init__("scheduler process transport failed after start")


_Parsed = TypeVar("_Parsed")


@dataclass(frozen=True)
class SchedulerRunnerAdapter:
    """The only public dormant M7 adapter; no generic command surface is exposed."""

    config: TrustedSchedulerConfig

    def __post_init__(self) -> None:
        if not isinstance(self.config, TrustedSchedulerConfig):
            raise SchedulerRunnerContractError("a trusted scheduler configuration is required")

    def submit_held(
        self,
        state: SchedulerPreflightState,
        *,
        permit: SchedulerMutationPermit,
    ) -> SlurmJobRef:
        """Submit the exact generated compute template once as a held job."""

        deadline = _permit_deadline(self.config, permit, "submit_held", state)
        _validate_state(self.config, state, {"prepared"})
        worker = state.manifest.worker
        spec = SlurmSubmitSpec(
            policy=state.manifest.scheduler_policy,
            submission_marker=state.submission_marker,
            working_directory=str(PurePosixPath(worker.manifest_path).parent),
            log_directory=str(PurePosixPath(worker.evidence_path).parent),
        )
        template = render_compute_template(state.manifest)
        if (
            template != state.template_bytes
            or hashlib.sha256(template).hexdigest() != state.template_sha256
        ):
            raise SchedulerRunnerContractError("compute template no longer matches preflight state")
        invocation = _make_invocation(
            self.config,
            operation="submit_held",
            argv=build_sbatch_argv(str(self.config.executables["sbatch"].path), spec),
            stdin_bytes=template,
            timeout_seconds=float(state.manifest.scheduler_policy.submit_timeout_seconds),
            deadline=deadline,
            state=state,
        )
        result: SchedulerCommandResult | None = None
        try:
            result = self._run_mutation(invocation)
            try:
                return parse_sbatch_parsable_output(result.stdout, state.submission_marker)
            except SlurmContractError:
                raise _mutation_unknown(result, "SCHEDULER_SUBMIT_OUTPUT_INVALID") from None
        except (SchedulerRunnerPreconditionError, SchedulerCommandStartError):
            raise
        except SchedulerMutationUnknown:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise _unexpected_mutation(
                invocation,
                result,
                reason_code="SCHEDULER_MUTATION_INTERRUPTED",
            ) from None
        except BaseException:
            raise _unexpected_mutation(
                invocation,
                result,
                reason_code="SCHEDULER_MUTATION_POST_TRANSPORT_FAILURE",
            ) from None

    def query_held(
        self,
        state: SchedulerPreflightState,
        job: SlurmJobRef,
    ) -> SlurmHeldJob | None:
        """Query exact evidence that one marker-bound job is still user-held."""

        deadline = _operation_deadline(self.config.contract.limits.command_timeout_seconds)
        _validate_state(self.config, state, {"prepared", "submit_unknown"})
        if not isinstance(job, SlurmJobRef) or job.submission_marker != state.submission_marker:
            raise SchedulerRunnerContractError("held query job does not bind this preflight")
        invocation = _make_invocation(
            self.config,
            operation="query_held",
            argv=build_squeue_hold_argv(str(self.config.executables["squeue"].path), job),
            stdin_bytes=None,
            timeout_seconds=self.config.contract.limits.command_timeout_seconds,
            deadline=deadline,
            state=state,
        )
        return self._run_query(
            invocation,
            lambda data: parse_squeue_hold_output(data, job),
        )

    def discover_submit(self, state: SchedulerPreflightState) -> SlurmObservation | None:
        """Perform the only positive marker discovery after an ambiguous submit."""

        deadline = _operation_deadline(self.config.contract.limits.command_timeout_seconds)
        _validate_state(self.config, state, {"submit_unknown"})
        invocation = _make_invocation(
            self.config,
            operation="discover_submit",
            argv=build_squeue_discovery_argv(
                str(self.config.executables["squeue"].path),
                state.submission_marker,
            ),
            stdin_bytes=None,
            timeout_seconds=self.config.contract.limits.command_timeout_seconds,
            deadline=deadline,
            state=state,
        )
        return self._run_query(
            invocation,
            lambda data: parse_squeue_discovery_output(data, state.submission_marker),
        )

    def release_held(
        self,
        state: SchedulerPreflightState,
        *,
        permit: SchedulerMutationPermit,
    ) -> SchedulerMutationReceipt:
        """Release only the exact held job from validated release-ready state."""

        deadline = _permit_deadline(self.config, permit, "release_held", state)
        _validate_state(self.config, state, {"release_ready"})
        if state.held_job is None:
            raise SchedulerRunnerContractError("release requires exact user-hold evidence")
        invocation = _make_invocation(
            self.config,
            operation="release_held",
            argv=build_scontrol_release_argv(
                str(self.config.executables["scontrol"].path),
                state.held_job,
            ),
            stdin_bytes=None,
            timeout_seconds=self.config.contract.limits.command_timeout_seconds,
            deadline=deadline,
            state=state,
        )
        result: SchedulerCommandResult | None = None
        try:
            result = self._run_mutation(invocation, require_empty_stdout=True)
            return SchedulerMutationReceipt(
                operation="release_held",
                invocation_sha256=result.invocation_sha256,
            )
        except (SchedulerRunnerPreconditionError, SchedulerCommandStartError):
            raise
        except SchedulerMutationUnknown:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise _unexpected_mutation(
                invocation,
                result,
                reason_code="SCHEDULER_MUTATION_INTERRUPTED",
            ) from None
        except BaseException:
            raise _unexpected_mutation(
                invocation,
                result,
                reason_code="SCHEDULER_MUTATION_POST_TRANSPORT_FAILURE",
            ) from None

    def query_queue(self, state: SchedulerPreflightState) -> SlurmObservation | None:
        """Run one exact allocation-level ``squeue`` observation."""

        deadline = _operation_deadline(self.config.contract.limits.command_timeout_seconds)
        _validate_state(self.config, state, set(_JOB_QUERY_PHASES))
        job = _state_job(state)
        invocation = _make_invocation(
            self.config,
            operation="query_queue",
            argv=build_squeue_argv(str(self.config.executables["squeue"].path), job),
            stdin_bytes=None,
            timeout_seconds=self.config.contract.limits.command_timeout_seconds,
            deadline=deadline,
            state=state,
        )
        return self._run_query(invocation, lambda data: parse_squeue_output(data, job))

    def query_accounting(self, state: SchedulerPreflightState) -> SlurmObservation | None:
        """Run one exact allocation-only ``sacct`` reconciliation query."""

        deadline = _operation_deadline(self.config.contract.limits.command_timeout_seconds)
        _validate_state(self.config, state, set(_JOB_QUERY_PHASES))
        job = _state_job(state)
        invocation = _make_invocation(
            self.config,
            operation="query_accounting",
            argv=build_sacct_argv(str(self.config.executables["sacct"].path), job),
            stdin_bytes=None,
            timeout_seconds=self.config.contract.limits.command_timeout_seconds,
            deadline=deadline,
            state=state,
        )
        return self._run_query(invocation, lambda data: parse_sacct_output(data, job))

    def _run_mutation(
        self,
        invocation: _Invocation,
        *,
        require_empty_stdout: bool = False,
    ) -> SchedulerCommandResult:
        try:
            result = _execute_invocation(self.config, invocation)
        except _PostStartFailure as exc:
            raise SchedulerMutationUnknown(
                operation=exc.operation,
                invocation_sha256=exc.invocation_sha256,
                reason_code=exc.reason_code,
                return_code=exc.return_code,
                timed_out=False,
                output_limit_exceeded=False,
                io_failed=True,
                stdin_sha256=invocation.stdin_sha256,
                stdin_size=invocation.stdin_size,
                stdin_bytes_written=exc.stdin_bytes_written,
            ) from None
        except (SchedulerRunnerPreconditionError, SchedulerCommandStartError):
            raise
        except (KeyboardInterrupt, SystemExit):
            raise _unexpected_mutation(
                invocation,
                reason_code="SCHEDULER_MUTATION_INTERRUPTED",
            ) from None
        except BaseException:
            raise _unexpected_mutation(
                invocation,
                reason_code="SCHEDULER_MUTATION_INTERNAL_FAILURE",
            ) from None
        if not result.transport_complete:
            raise _mutation_unknown(result, "SCHEDULER_MUTATION_TRANSPORT_INCOMPLETE")
        if result.return_code != 0:
            raise _mutation_unknown(result, "SCHEDULER_MUTATION_EXIT_NONZERO")
        if result.stderr:
            raise _mutation_unknown(result, "SCHEDULER_MUTATION_STDERR_NONEMPTY")
        if require_empty_stdout and result.stdout:
            raise _mutation_unknown(result, "SCHEDULER_RELEASE_STDOUT_NONEMPTY")
        return result

    def _run_query(
        self,
        invocation: _Invocation,
        parser: Callable[[bytes], _Parsed],
    ) -> _Parsed:
        try:
            result = _execute_invocation(self.config, invocation)
        except _PostStartFailure as exc:
            raise SchedulerQueryRetryableError(
                operation=exc.operation,
                invocation_sha256=exc.invocation_sha256,
                reason_code="SCHEDULER_QUERY_POST_START_IO_FAILURE",
            ) from None
        if not result.transport_complete:
            raise SchedulerQueryRetryableError(
                operation=result.operation,
                invocation_sha256=result.invocation_sha256,
                reason_code="SCHEDULER_QUERY_TRANSPORT_INCOMPLETE",
            )
        if result.return_code != 0:
            raise SchedulerQueryRetryableError(
                operation=result.operation,
                invocation_sha256=result.invocation_sha256,
                reason_code="SCHEDULER_QUERY_EXIT_NONZERO",
            )
        if result.stderr:
            raise SchedulerQueryRetryableError(
                operation=result.operation,
                invocation_sha256=result.invocation_sha256,
                reason_code="SCHEDULER_QUERY_STDERR_NONEMPTY",
            )
        try:
            return parser(result.stdout)
        except SlurmContractError:
            raise SchedulerQueryEvidenceError(
                result.operation,
                result.invocation_sha256,
            ) from None


def _validate_state(
    config: TrustedSchedulerConfig,
    state: SchedulerPreflightState,
    phases: set[str],
) -> None:
    if not isinstance(state, SchedulerPreflightState) or state.phase not in phases:
        raise SchedulerRunnerContractError(
            "scheduler preflight state is not valid for this operation"
        )
    manifest = state.manifest
    contract = config.contract
    if (
        manifest.profile_id != contract.profile_id
        or manifest.profile_hash != contract.profile_hash
        or manifest.scheduler_policy != contract.scheduler
        or manifest.scheduler_policy_hash != config.scheduler_policy_hash
    ):
        raise SchedulerRunnerContractError(
            "scheduler preflight state does not bind trusted config-v2"
        )
    try:
        rebuilt = prepare_preflight(manifest)
    except SchedulerPreflightError as exc:
        raise SchedulerRunnerContractError(
            "scheduler preflight state cannot be revalidated"
        ) from exc
    if (
        state.manifest_sha256 != rebuilt.manifest_sha256
        or state.template_bytes != rebuilt.template_bytes
        or state.template_sha256 != rebuilt.template_sha256
        or state.submission_marker != rebuilt.submission_marker
    ):
        raise SchedulerRunnerContractError(
            "scheduler preflight manifest or template identity changed"
        )
    _related_root_checks(config, state)


def _permit_deadline(
    config: TrustedSchedulerConfig,
    permit: SchedulerMutationPermit,
    operation: Literal["submit_held", "release_held"],
    state: SchedulerPreflightState,
) -> float:
    try:
        return _consume_mutation_permit(permit, operation, state, config)
    except SchedulerMutationPermitError as exc:
        raise SchedulerRunnerContractError(
            "a current unconsumed durable scheduler mutation permit is required"
        ) from exc


def _operation_deadline(timeout_seconds: float) -> float:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise SchedulerRunnerContractError("scheduler command timeout must be positive and finite")
    return time.monotonic() + timeout_seconds


def _related_root_checks(
    config: TrustedSchedulerConfig,
    state: SchedulerPreflightState,
) -> tuple[tuple[RootRole, int], ...]:
    """Bind every compute-visible manifest path to its configured role root."""

    manifest = state.manifest
    checks: set[tuple[RootRole, int]] = {("state", 0)}
    checks.add(
        (
            "state",
            _root_index(
                manifest.worker.manifest_path,
                config.state_root.path,
                "worker manifest",
            ),
        )
    )
    checks.add(
        (
            "state",
            _root_index(
                manifest.worker.evidence_path,
                config.state_root.path,
                "worker evidence",
            ),
        )
    )
    checks.add(("deploy", _role_root_index(manifest.deploy_dir, config.deploy_roots, "deploy")))
    checks.add(("work", _role_root_index(manifest.work_dir, config.work_roots, "work")))
    checks.add(("output", _role_root_index(manifest.output_dir, config.output_roots, "output")))
    checks.add(("cache", _role_root_index(manifest.cache_dir, config.cache_roots, "cache")))
    for path in manifest.execution_paths:
        checks.add(("read", _role_root_index(path, config.read_roots, "execution input")))
    for container in manifest.containers:
        checks.add(
            (
                "cache",
                _role_root_index(container.local_path, config.cache_roots, "SIF artifact"),
            )
        )
    order = {"state": 0, "read": 1, "deploy": 2, "work": 3, "output": 4, "cache": 5}
    return tuple(sorted(checks, key=lambda item: (order[item[0]], item[1])))


def _root_index(path: str, root: Path, label: str) -> int:
    candidate = PurePosixPath(path)
    configured = PurePosixPath(str(root))
    try:
        relative = candidate.relative_to(configured)
    except ValueError as exc:
        raise SchedulerRunnerContractError(
            f"{label} path is outside its trusted scheduler role root"
        ) from exc
    if not relative.parts:
        raise SchedulerRunnerContractError(
            f"{label} path must be a descendant of its trusted scheduler role root"
        )
    return 0


def _role_root_index(
    path: str,
    bindings: Sequence[TrustedDirectoryBinding],
    label: str,
) -> int:
    matches: list[int] = []
    candidate = PurePosixPath(path)
    for index, binding in enumerate(bindings):
        root = PurePosixPath(str(binding.path))
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        if relative.parts:
            matches.append(index)
    if len(matches) != 1:
        raise SchedulerRunnerContractError(
            f"{label} path does not bind exactly one trusted scheduler role root"
        )
    return matches[0]


def _state_job(state: SchedulerPreflightState) -> SlurmJobRef:
    if state.job is None:
        raise SchedulerRunnerContractError("scheduler query requires one exact bound job")
    return state.job


def _make_invocation(
    config: TrustedSchedulerConfig,
    *,
    operation: SchedulerOperation,
    argv: Sequence[str],
    stdin_bytes: bytes | None,
    timeout_seconds: float,
    state: SchedulerPreflightState,
    deadline: float | None = None,
) -> _Invocation:
    role = _OPERATION_ROLES[operation]
    arguments = tuple(argv)
    expected_executable = str(config.executables[role].path)
    if (
        not arguments
        or arguments[0] != expected_executable
        or any(not isinstance(value, str) or not value or "\x00" in value for value in arguments)
    ):
        raise SchedulerRunnerContractError("scheduler argv is outside the fixed operation contract")
    if operation == "submit_held":
        if type(stdin_bytes) is not bytes or not stdin_bytes:
            raise SchedulerRunnerContractError(
                "held submit requires exact non-empty template bytes"
            )
    elif stdin_bytes is not None:
        raise SchedulerRunnerContractError("scheduler queries and release must not receive stdin")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise SchedulerRunnerContractError("scheduler command timeout must be positive and finite")
    selected_deadline = (
        _operation_deadline(timeout_seconds) if deadline is None else float(deadline)
    )
    if not math.isfinite(selected_deadline):
        raise SchedulerRunnerContractError("scheduler operation deadline must be finite")
    output_limit = config.contract.limits.max_command_output_bytes
    if type(output_limit) is not int or output_limit < 1:
        raise SchedulerRunnerContractError("scheduler command output limit must be positive")
    environment = build_scheduler_environment(str(config.state_root.path))
    environment_hash = hashlib.sha256(
        json.dumps(
            dict(environment),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    stdin_sha256 = hashlib.sha256(stdin_bytes).hexdigest() if stdin_bytes is not None else None
    stdin_size = len(stdin_bytes) if stdin_bytes is not None else 0
    executable_sha256 = config.executables[role].sha256
    if executable_sha256 is None:
        raise SchedulerRunnerContractError("scheduler executable lacks its startup SHA-256")
    related_root_checks = _related_root_checks(config, state)
    root_checks = related_root_checks if operation in _MUTATION_OPERATIONS else (("state", 0),)
    root_identities = [
        _root_identity_for_hash(config, root_role, index) for root_role, index in root_checks
    ]
    identity_payload = json.dumps(
        {
            "operation": operation,
            "role": role,
            "argv": list(arguments),
            "cwd": str(config.state_root.path),
            "environment_sha256": environment_hash,
            "executable_sha256": executable_sha256,
            "stdin_sha256": stdin_sha256,
            "stdin_size": stdin_size,
            "timeout_seconds": float(timeout_seconds),
            "output_limit_bytes": output_limit,
            "config_sha256": config.config_sha256,
            "contract_sha256": config.contract_sha256,
            "root_identities": root_identities,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return _Invocation(
        operation=operation,
        role=role,
        argv=arguments,
        stdin_bytes=stdin_bytes,
        stdin_sha256=stdin_sha256,
        stdin_size=stdin_size,
        cwd=config.state_root.path,
        environment=environment,
        timeout_seconds=float(timeout_seconds),
        deadline=selected_deadline,
        output_limit_bytes=output_limit,
        invocation_sha256=hashlib.sha256(identity_payload).hexdigest(),
        root_checks=root_checks,
    )


def _root_identity_for_hash(
    config: TrustedSchedulerConfig,
    role: RootRole,
    index: int,
) -> dict[str, str | int]:
    binding = _root_binding(config, role, index)
    return {
        "role": role,
        "index": index,
        "path": str(binding.path),
        "device": binding.device,
        "inode": binding.inode,
        "owner": binding.owner,
        "group": binding.group,
        "mode": binding.mode,
    }


def _root_binding(
    config: TrustedSchedulerConfig,
    role: RootRole,
    index: int,
) -> TrustedDirectoryBinding:
    if role == "state":
        if index != 0:
            raise SchedulerRunnerContractError("state root index must be zero")
        return config.state_root
    bindings: Mapping[str, tuple[TrustedDirectoryBinding, ...]] = {
        "read": config.read_roots,
        "deploy": config.deploy_roots,
        "work": config.work_roots,
        "output": config.output_roots,
        "cache": config.cache_roots,
    }
    try:
        return bindings[role][index]
    except (KeyError, IndexError) as exc:
        raise SchedulerRunnerContractError("scheduler root check is invalid") from exc


def _execute_invocation(
    config: TrustedSchedulerConfig,
    invocation: _Invocation,
) -> SchedulerCommandResult:
    if os.name != "posix":
        raise SchedulerCommandStartError(invocation.operation, invocation.invocation_sha256)
    try:
        _require_pre_start_time(invocation)
        verify_scheduler_config_file(config)
        _require_pre_start_time(invocation)
        for role, index in invocation.root_checks:
            verify_scheduler_root(config, role, index)
            _require_pre_start_time(invocation)
        verify_scheduler_executable(config, invocation.role)
        _require_pre_start_time(invocation)
    except SchedulerConfigLoadError:
        raise SchedulerRunnerPreconditionError(
            invocation.operation,
            invocation.invocation_sha256,
        ) from None

    io_state = _IOState(invocation.output_limit_bytes)
    process: subprocess.Popen[bytes]
    try:
        process = subprocess.Popen(
            list(invocation.argv),
            stdin=subprocess.PIPE if invocation.stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=invocation.cwd,
            env=dict(invocation.environment),
            shell=False,
            text=False,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
            umask=0o077,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SchedulerCommandStartError(
            invocation.operation,
            invocation.invocation_sha256,
        ) from None
    except BaseException:
        if invocation.operation in _MUTATION_OPERATIONS:
            raise _PostStartFailure(
                invocation.operation,
                invocation.invocation_sha256,
                return_code=None,
                stdin_bytes_written=0,
                reason_code="SCHEDULER_MUTATION_START_UNCERTAIN",
            ) from None
        raise

    try:
        return _communicate_bounded(process, invocation, io_state)
    except BaseException as exc:
        _best_effort_cleanup(process)
        _stdout, _stderr, stdin_written = io_state.snapshot()
        if isinstance(exc, Exception) or invocation.operation in _MUTATION_OPERATIONS:
            reason_code = (
                "SCHEDULER_POST_START_IO_FAILURE"
                if isinstance(exc, Exception)
                else "SCHEDULER_MUTATION_INTERRUPTED"
            )
            raise _PostStartFailure(
                invocation.operation,
                invocation.invocation_sha256,
                return_code=process.returncode,
                stdin_bytes_written=stdin_written,
                reason_code=reason_code,
            ) from None
        raise


def _require_pre_start_time(invocation: _Invocation) -> None:
    if time.monotonic() >= invocation.deadline:
        raise SchedulerRunnerPreconditionError(
            invocation.operation,
            invocation.invocation_sha256,
            "SCHEDULER_OPERATION_DEADLINE_EXPIRED",
        )


def _communicate_bounded(
    process: subprocess.Popen[bytes],
    invocation: _Invocation,
    io_state: _IOState,
) -> SchedulerCommandResult:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("scheduler process pipes are unavailable")
    selector = selectors.DefaultSelector()
    stdin_view = memoryview(invocation.stdin_bytes or b"")
    stdin_position = 0
    deadline = invocation.deadline
    timed_out = False
    terminated = False
    process_exited_at: float | None = None
    try:
        _register_selector_pipe(
            selector,
            process.stdout,
            selectors.EVENT_READ,
            "read",
            "stdout",
        )
        _register_selector_pipe(
            selector,
            process.stderr,
            selectors.EVENT_READ,
            "read",
            "stderr",
        )
        if invocation.stdin_bytes is not None:
            if process.stdin is None:
                raise RuntimeError("scheduler submit stdin pipe is unavailable")
            _register_selector_pipe(selector, process.stdin, selectors.EVENT_WRITE, "write")
        while True:
            now = time.monotonic()
            if io_state.overflow or io_state.io_failed:
                terminated = True
                break
            if now >= deadline:
                timed_out = True
                terminated = True
                break
            return_code = process.poll()
            if return_code is not None:
                if process_exited_at is None:
                    process_exited_at = now
                if not selector.get_map():
                    break
                if now - process_exited_at >= _PROCESS_EXIT_DRAIN_SECONDS:
                    io_state.io_failed = True
                    terminated = True
                    break
            wait_for = min(_POLL_SECONDS, max(0.0, deadline - now))
            if process_exited_at is not None:
                wait_for = min(
                    wait_for,
                    max(
                        0.0,
                        process_exited_at + _PROCESS_EXIT_DRAIN_SECONDS - now,
                    ),
                )
            if selector.get_map():
                events = selector.select(wait_for)
            else:
                time.sleep(wait_for)
                events = []
            for key, _mask in events:
                target: _SelectorTarget = key.data
                descriptor = key.fd
                if target.direction == "read":
                    _read_selector_pipe(selector, descriptor, target, io_state)
                    continue
                if stdin_position >= len(stdin_view):
                    _close_selector_target(selector, descriptor, target)
                    continue
                try:
                    written = os.write(descriptor, stdin_view[stdin_position:])
                except BlockingIOError:
                    continue
                except OSError:
                    io_state.io_failed = True
                    _close_selector_target(selector, descriptor, target)
                    continue
                if written <= 0:
                    io_state.io_failed = True
                    _close_selector_target(selector, descriptor, target)
                    continue
                stdin_position += written
                io_state.record_stdin_write(written)
                if stdin_position == len(stdin_view):
                    _close_selector_target(selector, descriptor, target)
    finally:
        selector.close()

    cleanup_deadline = time.monotonic() + _CLEANUP_BUDGET_SECONDS
    if terminated:
        _terminate_process_group(process, cleanup_deadline)
    elif process.poll() is None:
        _terminate_process_group(process, cleanup_deadline)
        io_state.io_failed = True
    _close_process_streams(process)
    if process.poll() is None:
        _terminate_process_group(process, cleanup_deadline)

    stdout, stderr, stdin_written = io_state.snapshot()
    return SchedulerCommandResult(
        operation=invocation.operation,
        invocation_sha256=invocation.invocation_sha256,
        argv=invocation.argv,
        return_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        stdin_sha256=invocation.stdin_sha256,
        stdin_size=invocation.stdin_size,
        stdin_bytes_written=stdin_written,
        timed_out=timed_out,
        output_limit_exceeded=io_state.overflow,
        io_failed=io_state.io_failed,
    )


def _register_selector_pipe(
    selector: selectors.BaseSelector,
    pipe: IO[bytes],
    event: int,
    direction: Literal["read", "write"],
    stream: Literal["stdout", "stderr"] | None = None,
) -> None:
    descriptor = pipe.fileno()
    os.set_blocking(descriptor, False)
    selector.register(
        descriptor,
        event,
        _SelectorTarget(pipe=pipe, direction=direction, stream=stream),
    )


def _read_selector_pipe(
    selector: selectors.BaseSelector,
    descriptor: int,
    target: _SelectorTarget,
    state: _IOState,
) -> None:
    if target.stream is None:
        raise RuntimeError("scheduler output selector lacks a stream identity")
    try:
        chunk = os.read(descriptor, _CHUNK_BYTES)
    except BlockingIOError:
        return
    except OSError:
        state.io_failed = True
        _close_selector_target(selector, descriptor, target)
        return
    if not chunk:
        _close_selector_target(selector, descriptor, target)
        return
    state.consume(target.stream, chunk)


def _close_selector_target(
    selector: selectors.BaseSelector,
    descriptor: int,
    target: _SelectorTarget,
) -> None:
    with suppress(KeyError):
        selector.unregister(descriptor)
    _close(target.pipe)


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    cleanup_deadline: float,
) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    if process.poll() is None:
        grace = min(_TERM_GRACE_SECONDS, _remaining(cleanup_deadline))
        if grace > 0:
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=grace)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        remaining = _remaining(cleanup_deadline)
        if remaining > 0:
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=remaining)


def _best_effort_cleanup(process: subprocess.Popen[bytes]) -> None:
    """Never let cleanup failure erase an already ambiguous mutation result."""

    cleanup_deadline = time.monotonic() + _CLEANUP_BUDGET_SECONDS
    with suppress(BaseException):
        _terminate_process_group(process, cleanup_deadline)
    with suppress(BaseException):
        _close_process_streams(process)


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            _close(stream)


def _close(stream: IO[bytes]) -> None:
    with suppress(OSError, ValueError):
        stream.close()


def _mutation_unknown(
    result: SchedulerCommandResult,
    reason_code: str,
) -> SchedulerMutationUnknown:
    if result.operation not in _MUTATION_OPERATIONS:
        raise SchedulerRunnerContractError("only scheduler mutations can have unknown outcomes")
    return SchedulerMutationUnknown(
        operation=result.operation,
        invocation_sha256=result.invocation_sha256,
        reason_code=reason_code,
        return_code=result.return_code,
        timed_out=result.timed_out,
        output_limit_exceeded=result.output_limit_exceeded,
        io_failed=result.io_failed,
        stdin_sha256=result.stdin_sha256,
        stdin_size=result.stdin_size,
        stdin_bytes_written=result.stdin_bytes_written,
    )


def _unexpected_mutation(
    invocation: _Invocation,
    result: SchedulerCommandResult | None = None,
    *,
    reason_code: str,
) -> SchedulerMutationUnknown:
    if invocation.operation not in _MUTATION_OPERATIONS:
        raise SchedulerRunnerContractError("only scheduler mutations may have unknown outcomes")
    return SchedulerMutationUnknown(
        operation=invocation.operation,
        invocation_sha256=invocation.invocation_sha256,
        reason_code=reason_code,
        return_code=None if result is None else result.return_code,
        timed_out=False if result is None else result.timed_out,
        output_limit_exceeded=False if result is None else result.output_limit_exceeded,
        io_failed=True,
        stdin_sha256=invocation.stdin_sha256,
        stdin_size=invocation.stdin_size,
        stdin_bytes_written=0 if result is None else result.stdin_bytes_written,
    )


__all__ = [
    "SchedulerCommandStartError",
    "SchedulerMutationReceipt",
    "SchedulerMutationUnknown",
    "SchedulerQueryEvidenceError",
    "SchedulerQueryRetryableError",
    "SchedulerRunnerAdapter",
    "SchedulerRunnerContractError",
    "SchedulerRunnerPreconditionError",
]
