"""Behavioral tests for the dormant M7 scheduler subsystem.

These cover the structural gaps: the phase-gate transition matrix (every
mutation rejects snapshots in the wrong phase), journal replay adversarial
cases (broken chains, renumbered or missing revisions), intent CAS conflicts,
and slurm output parser fuzzing (malformed bytes must only ever surface as
``SlurmContractError``, never as an unexpected exception).
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_state as state_module
from bioexec.scheduler_state import (
    SchedulerMutationPermit,
    SchedulerStateConflictError,
    SchedulerStateInvalidError,
)
from bioexec.slurm import (
    SlurmContractError,
    SlurmJobRef,
    parse_sacct_output,
    parse_sbatch_parsable_output,
    parse_squeue_discovery_output,
    parse_squeue_hold_output,
    parse_squeue_output,
)

from .test_scheduler_state import (
    _REQUEST_SHA256,
    StateFixture,
    _consume,
    _create,
    _held_job,
    _held_snapshot,
    _new_store,
)
from .test_scheduler_state import (
    state_fixture as state_fixture,
)

_REVISION_1 = "00000000000000000001.json"


def _canonical_bytes(value: Any) -> bytes:
    # Mirrors bioexec.scheduler_state._canonical_json_bytes (trailing newline).
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _rewrite_revision(attempt: Path, name: str, mutate: Any) -> None:
    path = attempt / "revisions" / name
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_bytes(_canonical_bytes(value))


# ---------------------------------------------------------------------------
# 1. Phase-gate transition matrix: every mutation rejects the wrong phase.
# ---------------------------------------------------------------------------


def test_claim_release_rejects_non_held_phase(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    with pytest.raises(SchedulerStateConflictError), store.claim_release(
        prepared, elapsed_seconds=1
    ):
        pass


def test_poll_rejects_non_pollable_phase(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    with pytest.raises(SchedulerStateConflictError):
        store.record_scheduler_poll(
            prepared, queue=None, accounting=None, elapsed_seconds=1
        )


def test_claim_submit_rejects_already_advanced_phase(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    assert held.state.phase == "held"
    with pytest.raises(SchedulerStateConflictError), store.claim_submit(held):
        pass


def test_recovered_held_rejects_wrong_phase(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    with pytest.raises(SchedulerStateConflictError):
        store.record_recovered_held(prepared, _held_job(prepared.state))


def test_ingest_evidence_rejects_wrong_phase(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    with pytest.raises(SchedulerStateConflictError):
        store.ingest_worker_evidence(prepared, elapsed_seconds=1)


def test_release_claim_is_single_use(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1):
        pass
    fresh = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    with pytest.raises(SchedulerStateConflictError) as captured, store.claim_release(
        fresh, elapsed_seconds=1
    ):
        pass
    assert captured.value.reason_code == "SCHEDULER_RELEASE_ALREADY_CLAIMED"


def test_mutation_permit_cannot_cross_operations(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    with store.claim_submit(prepared) as permit:
        assert isinstance(permit, SchedulerMutationPermit)
        # A submit_held permit must not authorize a release_held consumption.
        with pytest.raises(state_module.SchedulerMutationPermitError):
            state_module._consume_mutation_permit(
                permit, "release_held", permit.state, store.config
            )


# ---------------------------------------------------------------------------
# 2. Journal replay adversarial cases.
# ---------------------------------------------------------------------------


def test_journal_rejects_broken_hash_chain(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    _rewrite_revision(
        state_fixture.attempt,
        _REVISION_1,
        lambda value: value.update({"previous_sha256": "f" * 64}),
    )
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_CHAIN_INVALID"


def test_journal_rejects_renumbered_revision(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    _rewrite_revision(
        state_fixture.attempt, _REVISION_1, lambda value: value.update({"revision": 7})
    )
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_CHAIN_INVALID"


def test_journal_terminal_deletion_rewinds_to_submit_intent(
    state_fixture: StateFixture,
) -> None:
    # Deleting the terminal revision rewinds the journal to the submit intent:
    # the loader replays to submit_unknown instead of failing.  This documents
    # the design (the journal is crash-recovery + corruption evidence under an
    # owner-only directory, not a tamper-proof log against the owner): a fresh
    # load cannot distinguish "revision deleted" from "revision never
    # appended", and every later mutation still re-validates phase gates.
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    (state_fixture.attempt / "revisions" / _REVISION_1).unlink()
    rewound = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert rewound.state.phase == "submit_unknown"
    assert rewound.submit_intent_sha256 is not None


def test_journal_rejects_deleted_non_terminal_revision(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    with store.claim_release(held, elapsed_seconds=1) as permit:
        _consume(permit, "release_held", store)
        store.record_release_success(permit, invocation_sha256="f" * 64)
    revisions = state_fixture.attempt / "revisions"
    assert (revisions / "00000000000000000002.json").is_file()
    (revisions / _REVISION_1).unlink()
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_SET_INVALID"


def test_journal_rejects_unexpected_revision_file(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    (state_fixture.attempt / "revisions" / "notes.txt").write_text("nope")
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_SET_INVALID"


def test_journal_rejects_tampered_non_terminal_event(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    held = _held_snapshot(state_fixture, store)
    # Append a second revision so revision 1 becomes non-terminal, then tamper
    # revision 1's event: the chain link held by revision 2 must break.
    with store.claim_release(held, elapsed_seconds=1) as permit:
        _consume(permit, "release_held", store)
        store.record_release_success(permit, invocation_sha256="f" * 64)
    revisions = state_fixture.attempt / "revisions"
    assert (revisions / "00000000000000000002.json").is_file()

    def tamper(value: Any) -> None:
        value["event"]["held_job"]["job"]["job_id"] = "99999"

    _rewrite_revision(state_fixture.attempt, _REVISION_1, tamper)
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_CHAIN_INVALID"


# ---------------------------------------------------------------------------
# 3. Intent CAS conflicts.
# ---------------------------------------------------------------------------


def test_stale_snapshot_cas_conflicts_on_mutation(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    # The same store advances the attempt; the previously returned snapshot is
    # now stale and its compare-and-swap must fail.
    with store.claim_submit(prepared):
        pass
    with pytest.raises(SchedulerStateConflictError) as captured, store.claim_submit(prepared):
        pass
    assert captured.value.reason_code == "SCHEDULER_STATE_CAS_CONFLICT"


def test_submit_intent_file_is_create_only(state_fixture: StateFixture) -> None:
    store = _new_store(state_fixture)
    prepared = _create(state_fixture, store)
    with store.claim_submit(prepared):
        pass
    intent = state_fixture.attempt / "submit.intent.json"
    assert intent.is_file()
    before = intent.read_bytes()
    # A restarted claim must not overwrite the burned intent.
    restarted = _new_store(state_fixture)
    recovered = restarted.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    with pytest.raises(SchedulerStateConflictError), restarted.claim_submit(recovered):
        pass
    assert intent.read_bytes() == before


# ---------------------------------------------------------------------------
# 4. Slurm parser fuzzing: malformed bytes never escape as other exceptions.
# ---------------------------------------------------------------------------

_MARKER = "a" * 64


def _expected_job() -> SlurmJobRef:
    return SlurmJobRef(
        job_id="12345",
        submission_marker=_MARKER,
        submitted_at="2026-01-01T00:00:00",
    )


def _fuzz_corpus() -> list[bytes]:
    seeds = [
        b"",
        b"\n",
        b"12345\n",
        b"12345;cluster\n",
        b"1|2026-01-01T00:00:00|name|PD|\n",
        b"\x00\xff\xfe invalid utf-8 \x80\n",
        b"12345|" + _MARKER.encode() + b"|\n",
        b"A" * 100_000 + b"\n",
        b"|\n" * 50,
        b"12345\n12345\n",
        b"-1\n",
        b"99999999999999999999999999\n",
    ]
    rng = random.Random(20261005)
    corpus = list(seeds)
    alphabet = b"0123456789|;:-_ PDCA\n\x00\xff"
    for _ in range(300):
        length = rng.randint(0, 120)
        corpus.append(bytes(rng.choice(alphabet) for _ in range(length)))
    # Mutations of realistic rows.
    good_squeue = (
        f"12345|2026-01-01T00:00:00|{_MARKER}|PD|".encode("ascii") + b"\n"
    )
    good_sbatch = b"12345\n"
    for base in (good_squeue, good_sbatch):
        for _ in range(100):
            mutated = bytearray(base)
            for _ in range(rng.randint(1, 4)):
                if mutated:
                    mutated[rng.randrange(len(mutated))] = rng.choice(alphabet)
            corpus.append(bytes(mutated))
    return corpus


@pytest.mark.parametrize("payload", _fuzz_corpus())
def test_slurm_parsers_only_raise_contract_errors(payload: bytes) -> None:
    job = _expected_job()
    parsers = (
        lambda data: parse_sbatch_parsable_output(data, _MARKER),
        lambda data: parse_squeue_output(data, job),
        lambda data: parse_squeue_hold_output(data, job),
        lambda data: parse_sacct_output(data, job),
        lambda data: parse_squeue_discovery_output(data, _MARKER),
    )
    for parse in parsers:
        try:
            parse(payload)
        except SlurmContractError:
            continue
        except (TypeError, ValueError) as exc:
            pytest.fail(f"parser leaked {type(exc).__name__}: {exc!r}")
