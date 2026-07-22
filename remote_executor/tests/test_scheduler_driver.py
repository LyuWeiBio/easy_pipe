"""End-to-end state/transport tests for the dormant one-step scheduler driver."""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_state as state_module
from bioexec.scheduler_clock import ClockSample
from bioexec.scheduler_driver import SchedulerDriverResult, SchedulerPreflightDriver
from bioexec.scheduler_preflight import (
    SchedulerPreflightState,
    canonical_evidence_bytes,
    parse_compute_evidence,
    preflight_overall_timeout_seconds,
)
from bioexec.scheduler_runner import (
    SchedulerCommandStartError,
    SchedulerMutationReceipt,
    SchedulerMutationUnknown,
    SchedulerRunnerContractError,
)
from bioexec.scheduler_state import SchedulerMutationPermit, SchedulerMutationPermitError
from bioexec.slurm import SlurmHeldJob, SlurmJobRef, SlurmObservation

from .test_scheduler_state import (
    _REQUEST_SHA256,
    StateFixture,
    _worker_evidence_value,
    state_fixture,
)

_SUBMITTED_AT = "2026-07-22T12:34:56"


class _MutableClock:
    def __init__(self, *, epoch_id: str = "test-boot", boottime_ns: int = 1) -> None:
        self.epoch_id = epoch_id
        self.boottime_ns = boottime_ns
        self.sample_calls = 0
        self.on_sample: Callable[[_MutableClock, int], None] | None = None

    def sample(self) -> ClockSample:
        self.sample_calls += 1
        if self.on_sample is not None:
            self.on_sample(self, self.sample_calls)
        return ClockSample(epoch_id=self.epoch_id, boottime_ns=self.boottime_ns)


class _FakeRunner:
    def __init__(self, fixture: StateFixture) -> None:
        self.fixture = fixture
        self.submit_calls = 0
        self.release_calls = 0
        self.discovery_calls = 0
        self.queue_calls = 0
        self.accounting_calls = 0
        self.submit_unknown = False
        self.release_unknown = False
        self.discovery_visible = True
        self.held_visible = True
        self.accounting_complete = True
        self.before_release_consume: Callable[[], None] | None = None
        self.before_queue_query: Callable[[], None] | None = None
        self.queue_start_error = False
        self.release_contract_error = False

    def submit_held(
        self,
        state: SchedulerPreflightState,
        *,
        permit: SchedulerMutationPermit,
    ) -> SlurmJobRef:
        self.submit_calls += 1
        state_module._consume_mutation_permit(
            permit,
            "submit_held",
            state,
            self.fixture.config,
        )
        if self.submit_unknown:
            raise _mutation_unknown("submit_held")
        return SlurmJobRef(job_id="12345", submission_marker=state.submission_marker)

    def query_held(
        self,
        state: SchedulerPreflightState,
        job: SlurmJobRef,
    ) -> SlurmHeldJob | None:
        del state
        if not self.held_visible:
            return None
        return SlurmHeldJob(
            job=SlurmJobRef(
                job_id=job.job_id,
                submission_marker=job.submission_marker,
                submitted_at=_SUBMITTED_AT,
            ),
            state="PENDING",
            reason="JobHeldUser",
        )

    def discover_submit(
        self,
        state: SchedulerPreflightState,
    ) -> SlurmObservation | None:
        self.discovery_calls += 1
        if not self.discovery_visible:
            return None
        return SlurmObservation(
            source="squeue",
            job=SlurmJobRef(
                job_id="12345",
                submission_marker=state.submission_marker,
                submitted_at=_SUBMITTED_AT,
            ),
            state="PENDING",
        )

    def release_held(
        self,
        state: SchedulerPreflightState,
        *,
        permit: SchedulerMutationPermit,
    ) -> SchedulerMutationReceipt:
        if self.before_release_consume is not None:
            self.before_release_consume()
        if self.release_contract_error:
            raise SchedulerRunnerContractError("synthetic runner contract failure")
        try:
            state_module._consume_mutation_permit(
                permit,
                "release_held",
                state,
                self.fixture.config,
            )
        except SchedulerMutationPermitError as exc:
            raise SchedulerRunnerContractError("synthetic permit rejection") from exc
        self.release_calls += 1
        if self.release_unknown:
            raise _mutation_unknown("release_held")
        return SchedulerMutationReceipt(
            operation="release_held",
            invocation_sha256="d" * 64,
        )

    def query_queue(
        self,
        state: SchedulerPreflightState,
    ) -> SlurmObservation | None:
        del state
        self.queue_calls += 1
        if self.before_queue_query is not None:
            self.before_queue_query()
        if self.queue_start_error:
            raise SchedulerCommandStartError("query_queue", "f" * 64)
        return None

    def query_accounting(
        self,
        state: SchedulerPreflightState,
    ) -> SlurmObservation | None:
        self.accounting_calls += 1
        if not self.accounting_complete:
            return None
        assert state.job is not None
        return SlurmObservation(
            source="sacct",
            job=state.job,
            state="COMPLETED",
            exit_code=(0, 0),
        )


def _mutation_unknown(operation: str) -> SchedulerMutationUnknown:
    return SchedulerMutationUnknown(
        operation=operation,  # type: ignore[arg-type]
        invocation_sha256="e" * 64,
        reason_code="SCHEDULER_MUTATION_TRANSPORT_INCOMPLETE",
        return_code=None,
        timed_out=True,
        output_limit_exceeded=False,
        io_failed=False,
        stdin_sha256=None,
        stdin_size=0,
        stdin_bytes_written=0,
    )


def _driver(
    fixture: StateFixture,
    clock: _MutableClock,
    runner: _FakeRunner,
) -> SchedulerPreflightDriver:
    driver = SchedulerPreflightDriver(fixture.config, clock=clock)
    driver._runner = runner  # type: ignore[assignment]
    return driver


def _advance(
    driver: SchedulerPreflightDriver,
    fixture: StateFixture,
) -> SchedulerDriverResult:
    return driver.start_or_poll(
        fixture.prepared.manifest,
        request_sha256=_REQUEST_SHA256,
    )


def _write_evidence(fixture: StateFixture, value: dict[str, Any]) -> None:
    evidence = parse_compute_evidence(value)
    path = fixture.attempt / "evidence.json"
    path.write_bytes(canonical_evidence_bytes(evidence))
    path.chmod(0o600)


def _overall_deadline_ns(fixture: StateFixture, state: SchedulerPreflightState) -> int:
    intent = json.loads((fixture.attempt / "submit.intent.json").read_text(encoding="ascii"))
    return int(intent["clock_started_boottime_ns"]) + (
        preflight_overall_timeout_seconds(state) * 1_000_000_000
    )


def test_driver_reaches_candidate_in_four_bounded_calls_and_replays_without_evidence_file(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)

    held = _advance(driver, state_fixture)
    assert (held.status, held.revision, held.preflight_token) == ("held", 1, None)

    clock.boottime_ns = 2_000_000_000
    polling = _advance(driver, state_fixture)
    assert (polling.status, polling.revision) == ("polling", 2)

    clock.boottime_ns = 3_000_000_000
    awaiting = _advance(driver, state_fixture)
    assert (awaiting.status, awaiting.revision) == ("awaiting_evidence", 3)

    _write_evidence(state_fixture, _worker_evidence_value(awaiting_state(driver, state_fixture)))
    clock.boottime_ns = 4_000_000_000
    candidate = _advance(driver, state_fixture)
    assert (candidate.status, candidate.revision, candidate.preflight_token) == (
        "candidate",
        4,
        None,
    )
    assert candidate.evidence_sha256 is not None
    assert (runner.submit_calls, runner.release_calls) == (1, 1)

    (state_fixture.attempt / "evidence.json").unlink()
    restarted = _driver(state_fixture, clock, runner)
    replayed = _advance(restarted, state_fixture)
    assert replayed == candidate
    assert (runner.submit_calls, runner.release_calls) == (1, 1)


def test_driver_treats_separately_issued_passed_state_as_nonretryable_and_tokenless(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    _advance(driver, state_fixture)
    clock.boottime_ns = 2_000_000_000
    _advance(driver, state_fixture)
    clock.boottime_ns = 3_000_000_000
    _advance(driver, state_fixture)
    _write_evidence(state_fixture, _worker_evidence_value(awaiting_state(driver, state_fixture)))
    clock.boottime_ns = 4_000_000_000
    assert _advance(driver, state_fixture).status == "candidate"
    snapshot = driver._store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    monkeypatch.setattr(state_module.secrets, "token_hex", lambda length: "a1" * length)
    clock.boottime_ns = 5_000_000_000
    issuance = driver._store.issue_capability(snapshot)
    assert issuance.preflight_token == "a1" * 32

    result = _advance(driver, state_fixture)
    assert (result.status, result.retry_after_seconds, result.preflight_token) == (
        "passed",
        None,
        None,
    )


def awaiting_state(
    driver: SchedulerPreflightDriver,
    fixture: StateFixture,
) -> SchedulerPreflightState:
    return driver._store.load(
        fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    ).state


def test_missing_and_failed_worker_evidence_never_become_candidate(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    _advance(driver, state_fixture)
    clock.boottime_ns = 2_000_000_000
    _advance(driver, state_fixture)
    clock.boottime_ns = 3_000_000_000
    _advance(driver, state_fixture)

    clock.boottime_ns = 4_000_000_000
    pending = _advance(driver, state_fixture)
    assert pending.status == "awaiting_evidence"
    assert pending.code == "SCHEDULER_WORKER_EVIDENCE_PENDING"
    assert pending.revision == 3

    value = _worker_evidence_value(awaiting_state(driver, state_fixture))
    value["status"] = "failed"
    value["checks"][0]["status"] = "failed"
    value["checks"][0]["code"] = "COMPUTE_ALLOCATION_MISMATCH"
    value["checks"][0]["evidence_sha256"] = hashlib.sha256(b"failed").hexdigest()
    _write_evidence(state_fixture, value)
    failed = _advance(driver, state_fixture)
    assert failed.status == "failed"
    assert failed.code == "COMPUTE_ALLOCATION_MISMATCH"
    assert failed.preflight_token is None


def test_ambiguous_submit_is_recovered_by_read_only_discovery_without_resubmit(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    runner.submit_unknown = True
    driver = _driver(state_fixture, clock, runner)

    unknown = _advance(driver, state_fixture)
    assert unknown.status == "submit_unknown"
    assert unknown.code == "SCHEDULER_MUTATION_TRANSPORT_INCOMPLETE"
    runner.submit_unknown = False

    clock.boottime_ns = 2_000_000_000
    held = _advance(driver, state_fixture)
    assert held.status == "held"
    assert (runner.submit_calls, runner.discovery_calls) == (1, 1)

    repeated = _advance(driver, state_fixture)
    assert repeated.status == "polling"
    assert runner.submit_calls == 1


def test_ambiguous_release_is_never_replayed(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"

    runner.release_unknown = True
    clock.boottime_ns = 2_000_000_000
    unknown = _advance(driver, state_fixture)
    assert unknown.status == "release_unknown"
    assert runner.release_calls == 1

    runner.release_unknown = False
    clock.boottime_ns = 3_000_000_000
    recovered = _advance(driver, state_fixture)
    assert recovered.status == "awaiting_evidence"
    assert runner.release_calls == 1


def test_clock_epoch_change_and_overall_timeout_block_release_before_mutation(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"

    clock.epoch_id = "other-boot"
    invalidated = _advance(driver, state_fixture)
    assert invalidated.status == "indeterminate"
    assert invalidated.code == "SCHEDULER_CLOCK_DISCONTINUITY"
    assert runner.release_calls == 0


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        ("deadline", "timed_out", "SLURM_PREFLIGHT_OVERALL_TIMEOUT"),
        ("epoch", "indeterminate", "SCHEDULER_CLOCK_DISCONTINUITY"),
    ],
)
def test_claim_release_clock_failure_returns_the_first_terminal_result(
    state_fixture: StateFixture,
    failure: str,
    status: str,
    code: str,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    trigger_call = clock.sample_calls + 3
    deadline = _overall_deadline_ns(
        state_fixture,
        awaiting_state(driver, state_fixture),
    )

    def fail_on_claim_release(current: _MutableClock, call: int) -> None:
        if call != trigger_call:
            return
        if failure == "epoch":
            current.epoch_id = "other-boot"
        else:
            current.boottime_ns = deadline

    clock.on_sample = fail_on_claim_release
    terminal = _advance(driver, state_fixture)

    assert (terminal.status, terminal.code, terminal.preflight_token) == (
        status,
        code,
        None,
    )
    assert runner.release_calls == 0
    assert _advance(driver, state_fixture) == terminal


def test_release_deadline_crossing_inside_runner_blocks_process_creation(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    deadline = _overall_deadline_ns(
        state_fixture,
        awaiting_state(driver, state_fixture),
    )
    runner.before_release_consume = lambda: setattr(clock, "boottime_ns", deadline)

    terminal = _advance(driver, state_fixture)

    assert terminal.status == "timed_out"
    assert terminal.code == "SLURM_PREFLIGHT_OVERALL_TIMEOUT"
    assert runner.release_calls == 0
    assert _advance(driver, state_fixture) == terminal


def test_release_pre_intent_local_deadline_is_sanitized_without_mutation(
    state_fixture: StateFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    monotonic = iter((10.0, 10.0, 11.0))
    monkeypatch.setattr(state_module.time, "monotonic", lambda: next(monotonic))

    blocked = _advance(driver, state_fixture)

    assert blocked.status == "held"
    assert blocked.code == "SCHEDULER_MUTATION_DEADLINE_EXPIRED"
    assert blocked.retry_after_seconds is None
    assert runner.release_calls == 0
    assert not (state_fixture.attempt / "release.intent.json").exists()


def test_internal_runner_contract_error_is_not_mislabeled_as_a_permit_failure(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    runner.release_contract_error = True

    with pytest.raises(SchedulerRunnerContractError, match="synthetic runner contract"):
        _advance(driver, state_fixture)

    persisted = driver._store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert persisted.state.phase == "release_unknown"
    assert runner.release_calls == 0


def test_poll_rechecks_the_clock_after_scheduler_queries(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    clock.boottime_ns = 2_000_000_000
    assert _advance(driver, state_fixture).status == "polling"
    deadline = _overall_deadline_ns(
        state_fixture,
        awaiting_state(driver, state_fixture),
    )
    runner.before_queue_query = lambda: setattr(clock, "boottime_ns", deadline)

    terminal = _advance(driver, state_fixture)

    assert terminal.status == "timed_out"
    assert terminal.code == "SLURM_PREFLIGHT_OVERALL_TIMEOUT"
    assert terminal.evidence_sha256 is None


def test_read_only_query_start_failure_is_retryable_without_a_revision(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    clock.boottime_ns = 2_000_000_000
    polling = _advance(driver, state_fixture)
    assert polling.status == "polling"
    runner.queue_start_error = True

    failed = _advance(driver, state_fixture)

    assert failed.status == "polling"
    assert failed.code == "SCHEDULER_COMMAND_START_FAILED"
    assert failed.retry_after_seconds is not None
    assert failed.revision == polling.revision


def test_evidence_ingest_rechecks_clock_after_the_stable_read(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    assert _advance(driver, state_fixture).status == "held"
    clock.boottime_ns = 2_000_000_000
    assert _advance(driver, state_fixture).status == "polling"
    clock.boottime_ns = 3_000_000_000
    awaiting = _advance(driver, state_fixture)
    assert awaiting.status == "awaiting_evidence"
    _write_evidence(
        state_fixture,
        _worker_evidence_value(awaiting_state(driver, state_fixture)),
    )
    deadline = _overall_deadline_ns(
        state_fixture,
        awaiting_state(driver, state_fixture),
    )
    trigger_call = clock.sample_calls + 3

    def expire_during_ingest(current: _MutableClock, call: int) -> None:
        if call == trigger_call:
            current.boottime_ns = deadline

    clock.on_sample = expire_during_ingest
    terminal = _advance(driver, state_fixture)

    assert terminal.status == "timed_out"
    assert terminal.code == "SLURM_PREFLIGHT_OVERALL_TIMEOUT"
    assert terminal.evidence_sha256 is None
    revision = json.loads(
        (state_fixture.attempt / "revisions" / f"{terminal.revision:020d}.json").read_text(
            encoding="ascii"
        )
    )
    assert revision["event"]["type"] == "driver_timeout"


def test_candidate_deadline_is_irreversible_and_never_mints_a_token(
    state_fixture: StateFixture,
) -> None:
    clock = _MutableClock(boottime_ns=1_000_000_000)
    runner = _FakeRunner(state_fixture)
    driver = _driver(state_fixture, clock, runner)
    _advance(driver, state_fixture)
    clock.boottime_ns = 2_000_000_000
    _advance(driver, state_fixture)
    clock.boottime_ns = 3_000_000_000
    _advance(driver, state_fixture)
    _write_evidence(state_fixture, _worker_evidence_value(awaiting_state(driver, state_fixture)))
    clock.boottime_ns = 4_000_000_000
    assert _advance(driver, state_fixture).status == "candidate"

    clock.boottime_ns = 2_000_000_000_000
    timed_out = _advance(driver, state_fixture)
    assert timed_out.status == "timed_out"
    assert timed_out.preflight_token is None
    assert _advance(driver, state_fixture) == timed_out


def test_driver_source_stays_dormant_and_has_no_capability_or_loop_surface() -> None:
    source_path = Path(state_module.__file__).with_name("scheduler_driver.py")
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "issue_capability" not in source
    assert "consume_capability" not in source
    assert "preflight_token: None" in source
    assert not any(isinstance(node, (ast.While, ast.AsyncFor)) for node in ast.walk(tree))
    assert "sleep(" not in source

    for leaf in ("main.py", "commands.py", "protocol.py", "runner.py"):
        candidate = source_path.with_name(leaf)
        imports = candidate.read_text(encoding="utf-8")
        assert "scheduler_driver" not in imports


# Re-export the imported fixture for pytest discovery in this module.
assert state_fixture
