"""Dormant start-or-one-poll orchestration for M7 compute preflight.

This module joins the trusted scheduler loader, append-only state store, fixed
Slurm transport, and compute-worker evidence.  It is deliberately absent from
every installed version-1 entry point and stops at the non-authorizing
``candidate`` phase: it never creates, persists, returns, or consumes a
capability token.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .scheduler_clock import SchedulerClock, SystemSchedulerClock
from .scheduler_config_loader import TrustedSchedulerConfig, load_trusted_scheduler_config
from .scheduler_preflight import (
    ComputePreflightManifest,
    PreflightPhase,
    SchedulerPreflightState,
    prepare_preflight,
)
from .scheduler_runner import (
    SchedulerCommandStartError,
    SchedulerMutationUnknown,
    SchedulerQueryEvidenceError,
    SchedulerQueryRetryableError,
    SchedulerRunnerAdapter,
    SchedulerRunnerContractError,
    SchedulerRunnerPreconditionError,
)
from .scheduler_state import (
    SchedulerClockDiscontinuityError,
    SchedulerPreflightStore,
    SchedulerStateDeadlineError,
    SchedulerStatePreconditionError,
    SchedulerStateSnapshot,
    SchedulerWorkerEvidencePending,
)

_TERMINAL_PHASES = frozenset({"failed", "indeterminate", "timed_out"})
_POLL_PHASES = frozenset({"release_unknown", "polling"})


@dataclass(frozen=True)
class SchedulerDriverResult:
    """One bounded, sanitized view of a durable driver step."""

    preflight_id: str
    status: PreflightPhase
    code: str
    retry_after_seconds: int | None
    revision: int
    manifest_sha256: str
    template_sha256: str
    evidence_sha256: str | None
    job_id: str | None
    preflight_token: None = None


@dataclass
class SchedulerPreflightDriver:
    """Advance one exact compute preflight by at most one durable transition."""

    config: TrustedSchedulerConfig
    clock: SchedulerClock = field(default_factory=SystemSchedulerClock, repr=False)
    _store: SchedulerPreflightStore = field(init=False, repr=False)
    _runner: SchedulerRunnerAdapter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.config, TrustedSchedulerConfig):
            raise TypeError("trusted scheduler configuration is required")
        self._store = SchedulerPreflightStore(self.config, clock=self.clock)
        self._runner = SchedulerRunnerAdapter(self.config)

    @classmethod
    def from_config_path(cls, path: Path) -> SchedulerPreflightDriver:
        """Load one explicit trusted config without version-1 discovery."""

        return cls(load_trusted_scheduler_config(path))

    def start_or_poll(
        self,
        manifest: ComputePreflightManifest,
        *,
        request_sha256: str,
    ) -> SchedulerDriverResult:
        """Create/load one attempt and perform one phase-specific action."""

        prepared = prepare_preflight(manifest)
        snapshot = self._store.create_or_load(prepared, request_sha256=request_sha256)
        phase = snapshot.state.phase
        if phase == "prepared":
            return self._submit_once(snapshot)
        if phase == "submit_unknown":
            observed = self._clock_and_deadline(snapshot)
            if isinstance(observed, SchedulerDriverResult):
                return observed
            return self._recover_submit(observed[0])
        if phase == "held":
            observed = self._clock_and_deadline(snapshot)
            if isinstance(observed, SchedulerDriverResult):
                return observed
            return self._release_once(observed[0], elapsed_seconds=observed[1])
        if phase in _POLL_PHASES:
            observed = self._clock_and_deadline(snapshot)
            if isinstance(observed, SchedulerDriverResult):
                return observed
            return self._poll_scheduler(observed[0], elapsed_seconds=observed[1])
        if phase == "awaiting_evidence":
            observed = self._clock_and_deadline(snapshot)
            if isinstance(observed, SchedulerDriverResult):
                return observed
            return self._ingest_evidence(observed[0], elapsed_seconds=observed[1])
        if phase == "candidate":
            observed = self._clock_and_deadline(snapshot)
            if isinstance(observed, SchedulerDriverResult):
                return observed
            return self._result(observed[0])
        return self._result(snapshot)

    def _submit_once(self, snapshot: SchedulerStateSnapshot) -> SchedulerDriverResult:
        try:
            recovery_code = "SCHEDULER_HELD_EVIDENCE_PENDING"
            recovery_retry = True
            with self._store.claim_submit(snapshot) as permit:
                job = self._runner.submit_held(permit.state, permit=permit)
                try:
                    held = self._runner.query_held(permit.recovery_state, job)
                except SchedulerQueryRetryableError as exc:
                    held = None
                    recovery_code = exc.reason_code
                except SchedulerQueryEvidenceError:
                    held = None
                    recovery_code = "SCHEDULER_QUERY_EVIDENCE_INVALID"
                    recovery_retry = False
                if held is not None:
                    current = self._store.record_held(permit, held)
                    return self._result(current)
            return self._reload_result(
                snapshot,
                code=recovery_code,
                retry=recovery_retry,
            )
        except SchedulerRunnerPreconditionError as exc:
            return self._reload_result(snapshot, code=exc.reason_code, retry=False)
        except SchedulerCommandStartError:
            return self._reload_result(
                snapshot,
                code="SCHEDULER_COMMAND_START_FAILED",
                retry=True,
            )
        except SchedulerMutationUnknown as exc:
            return self._reload_result(snapshot, code=exc.reason_code, retry=True)
        except SchedulerRunnerContractError:
            terminal = self._reload_terminal(snapshot)
            if terminal is not None:
                return terminal
            raise
        except SchedulerStatePreconditionError as exc:
            return self._result(snapshot, code=exc.reason_code, retry=False)

    def _recover_submit(self, snapshot: SchedulerStateSnapshot) -> SchedulerDriverResult:
        try:
            discovered = self._runner.discover_submit(snapshot.state)
            if discovered is None:
                return self._result(
                    snapshot,
                    code="SCHEDULER_SUBMIT_DISCOVERY_PENDING",
                    retry=True,
                )
            held = self._runner.query_held(snapshot.state, discovered.job)
            if held is None:
                return self._result(
                    snapshot,
                    code="SCHEDULER_HELD_EVIDENCE_PENDING",
                    retry=True,
                )
            return self._result(self._store.record_recovered_held(snapshot, held))
        except SchedulerQueryRetryableError as exc:
            return self._result(snapshot, code=exc.reason_code, retry=True)
        except SchedulerQueryEvidenceError:
            return self._result(
                snapshot,
                code="SCHEDULER_QUERY_EVIDENCE_INVALID",
                retry=False,
            )
        except SchedulerCommandStartError:
            return self._result(
                snapshot,
                code="SCHEDULER_COMMAND_START_FAILED",
                retry=True,
            )
        except SchedulerRunnerPreconditionError as exc:
            return self._result(snapshot, code=exc.reason_code, retry=False)

    def _release_once(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        elapsed_seconds: int,
    ) -> SchedulerDriverResult:
        try:
            with self._store.claim_release(
                snapshot,
                elapsed_seconds=elapsed_seconds,
            ) as permit:
                receipt = self._runner.release_held(permit.state, permit=permit)
                current = self._store.record_release_success(
                    permit,
                    invocation_sha256=receipt.invocation_sha256,
                )
                return self._result(current)
        except SchedulerRunnerPreconditionError as exc:
            return self._reload_result(snapshot, code=exc.reason_code, retry=False)
        except SchedulerCommandStartError:
            return self._reload_result(
                snapshot,
                code="SCHEDULER_COMMAND_START_FAILED",
                retry=True,
            )
        except SchedulerMutationUnknown as exc:
            return self._reload_result(snapshot, code=exc.reason_code, retry=True)
        except SchedulerRunnerContractError:
            terminal = self._reload_terminal(snapshot)
            if terminal is not None:
                return terminal
            raise
        except SchedulerStateDeadlineError as exc:
            return self._result(exc.snapshot)
        except SchedulerClockDiscontinuityError as exc:
            return self._result(exc.snapshot)
        except SchedulerStatePreconditionError as exc:
            return self._result(snapshot, code=exc.reason_code, retry=False)

    def _poll_scheduler(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        elapsed_seconds: int,
    ) -> SchedulerDriverResult:
        try:
            queue = self._runner.query_queue(snapshot.state)
            accounting = self._runner.query_accounting(snapshot.state)
        except SchedulerQueryRetryableError as exc:
            return self._result(snapshot, code=exc.reason_code, retry=True)
        except SchedulerQueryEvidenceError:
            return self._result(
                snapshot,
                code="SCHEDULER_QUERY_EVIDENCE_INVALID",
                retry=False,
            )
        except SchedulerCommandStartError:
            return self._result(
                snapshot,
                code="SCHEDULER_COMMAND_START_FAILED",
                retry=True,
            )
        except SchedulerRunnerPreconditionError as exc:
            return self._result(snapshot, code=exc.reason_code, retry=False)
        current = self._store.record_scheduler_poll(
            snapshot,
            queue=queue,
            accounting=accounting,
            elapsed_seconds=elapsed_seconds,
        )
        return self._result(current)

    def _ingest_evidence(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        elapsed_seconds: int,
    ) -> SchedulerDriverResult:
        try:
            current = self._store.ingest_worker_evidence(
                snapshot,
                elapsed_seconds=elapsed_seconds,
            )
        except SchedulerWorkerEvidencePending as exc:
            return self._result(snapshot, code=exc.reason_code, retry=True)
        return self._result(current)

    def _clock_and_deadline(
        self,
        snapshot: SchedulerStateSnapshot,
    ) -> tuple[SchedulerStateSnapshot, int] | SchedulerDriverResult:
        observed, elapsed = self._store.observe_elapsed(snapshot)
        if elapsed is None:
            return self._result(observed)
        current = self._store.record_timeout_if_due(observed, elapsed_seconds=elapsed)
        if current.state.phase in _TERMINAL_PHASES:
            return self._result(current)
        return current, elapsed

    def _reload_result(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        code: str,
        retry: bool,
    ) -> SchedulerDriverResult:
        current = self._store.load(
            snapshot.state.manifest.preflight_id,
            request_sha256=snapshot.request_sha256,
        )
        if current.state.phase in _TERMINAL_PHASES:
            return self._result(current)
        return self._result(current, code=code, retry=retry)

    def _reload_terminal(
        self,
        snapshot: SchedulerStateSnapshot,
    ) -> SchedulerDriverResult | None:
        """Return only a durable terminal created by an in-flight permit guard."""

        current = self._store.load(
            snapshot.state.manifest.preflight_id,
            request_sha256=snapshot.request_sha256,
        )
        if current.state.phase in _TERMINAL_PHASES:
            return self._result(current)
        return None

    def _result(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        code: str | None = None,
        retry: bool | None = None,
    ) -> SchedulerDriverResult:
        state: SchedulerPreflightState = snapshot.state
        if retry is None:
            retry = state.phase not in _TERMINAL_PHASES | {"candidate"}
        return SchedulerDriverResult(
            preflight_id=state.manifest.preflight_id,
            status=state.phase,
            code=state.reason_code if code is None else code,
            retry_after_seconds=(
                state.manifest.scheduler_policy.status_poll_seconds if retry else None
            ),
            revision=snapshot.revision,
            manifest_sha256=state.manifest_sha256,
            template_sha256=state.template_sha256,
            evidence_sha256=state.evidence_sha256,
            job_id=state.job.job_id if state.job is not None else None,
        )


__all__ = ["SchedulerDriverResult", "SchedulerPreflightDriver"]
