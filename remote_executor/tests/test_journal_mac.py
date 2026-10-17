"""Tests for the journal HMAC integrity chain (M-B, ADR 0014).

Every scheduler journal revision carries ``journal_mac`` chained to its
predecessor, keyed by the approval HMAC key (which compute nodes never hold).
These tests prove the chain rejects what the plain hash chain cannot: a
same-uid full-tail rewrite that keeps ``previous_sha256`` links intact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_state as state_module
from bioexec.scheduler_bindings import expected_worker_paths
from bioexec.scheduler_config_loader import load_trusted_scheduler_config
from bioexec.scheduler_preflight import prepare_preflight
from bioexec.scheduler_state import (
    SchedulerStateContractError,
    SchedulerStateInvalidError,
)

from .test_scheduler_state import _NAMESPACE as _PREFLIGHT_NAMESPACE
from .test_scheduler_state import (
    _REQUEST_SHA256,
    StateFixture,
    _consume,
    _held_snapshot,
    _new_store,
    _write_canonical,
)
from .test_scheduler_state import (
    state_fixture as state_fixture,  # pytest fixture re-export
)


def _revision_path(attempt: Path, number: int) -> Path:
    return attempt / "revisions" / f"{number:020d}.json"


def _read_revision(attempt: Path, number: int) -> dict[str, Any]:
    return json.loads(_revision_path(attempt, number).read_text(encoding="ascii"))


def _two_revision_attempt(fixture: StateFixture):
    """Create an attempt with two chained revisions (held + release)."""
    store = _new_store(fixture)
    held = _held_snapshot(fixture, store)
    with store.claim_release(held, elapsed_seconds=1) as permit:
        _consume(permit, "release_held", store)
        terminal = store.record_release_success(permit, invocation_sha256="f" * 64)
    return store, terminal


def test_journal_mac_happy_path_verifies(state_fixture: StateFixture) -> None:
    store, terminal = _two_revision_attempt(state_fixture)
    assert terminal.revision == 2
    assert len(terminal.journal_mac) == 64
    reloaded = store.load(
        state_fixture.prepared.manifest.preflight_id,
        request_sha256=_REQUEST_SHA256,
    )
    assert reloaded.journal_mac == terminal.journal_mac
    assert reloaded.journal_sha256 == terminal.journal_sha256
    # The stored MAC matches a locally recomputed chain.
    key = state_fixture.config.contract.approval_hmac_key
    assert key is not None
    identity_sha256 = hashlib.sha256(
        (state_fixture.attempt / "identity.json").read_bytes()
    ).hexdigest()
    mac = state_module._journal_genesis_mac(key, identity_sha256)
    for number in (1, 2):
        value = _read_revision(state_fixture.attempt, number)
        unsealed = {k: v for k, v in value.items() if k != "journal_mac"}
        mac = state_module._journal_revision_mac(key, mac, unsealed)
        assert value["journal_mac"] == mac


def test_journal_mac_rejects_tampered_terminal_revision(
    state_fixture: StateFixture,
) -> None:
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    path = _revision_path(state_fixture.attempt, 1)
    value = _read_revision(state_fixture.attempt, 1)
    value["event"]["held_job"]["job"]["job_id"] = "99999"
    _write_canonical(path, value)
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_MAC_INVALID"


def test_journal_mac_rejects_full_tail_rewrite_with_intact_hash_chain(
    state_fixture: StateFixture,
) -> None:
    """The M-B attack: rewrite every revision, keep previous_sha256 links valid.

    The attacker recomputes the plain hash chain (and even the grant binding
    hash, which is unkeyed SHA-256) but cannot forge the HMAC chain without
    the approval key.  The load must still fail closed.
    """
    _two_revision_attempt(state_fixture)
    attempt = state_fixture.attempt
    identity_sha256 = hashlib.sha256((attempt / "identity.json").read_bytes()).hexdigest()

    previous = identity_sha256
    for number in (1, 2):
        value = _read_revision(attempt, number)
        # Tamper the event payload but keep the hash chain perfectly intact.
        value["event"]["tampered_by_test"] = True
        value["previous_sha256"] = previous
        value.pop("journal_mac")  # attacker cannot forge a new one; keep stale
        raw = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        previous = hashlib.sha256(raw).hexdigest()
        # Write the tampered revision back with its *stale* MAC.
        original = _read_revision(attempt, number)
        tampered = dict(value)
        tampered["journal_mac"] = original["journal_mac"]
        _write_canonical(_revision_path(attempt, number), tampered)

    store = _new_store(state_fixture)
    with pytest.raises(SchedulerStateInvalidError) as captured:
        store.load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_REVISION_MAC_INVALID"


def test_journal_mac_rejects_key_id_mismatch(state_fixture: StateFixture) -> None:
    """Key rotation retires in-flight journals: fail closed, explicit code.

    The journal is sealed under one approval key id; presenting it with the
    identity rewritten to a rotated key id must be refused before any MAC is
    even checked (the operator cannot have the new key seal the old journal).
    """
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    identity_path = state_fixture.attempt / "identity.json"
    identity = json.loads(identity_path.read_text(encoding="ascii"))
    identity["journal_key_id"] = "rotated-key-2026-10"
    _write_canonical(identity_path, identity)
    with pytest.raises(SchedulerStateInvalidError) as captured:
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )
    assert captured.value.reason_code == "SCHEDULER_JOURNAL_KEY_MISMATCH"


def test_journal_mac_rejects_legacy_format_without_mac(
    state_fixture: StateFixture,
) -> None:
    """Pre-MAC (schema 1.4) journals are rejected explicitly, never accepted."""
    store = _new_store(state_fixture)
    _held_snapshot(state_fixture, store)
    attempt = state_fixture.attempt

    identity_path = attempt / "identity.json"
    identity = json.loads(identity_path.read_text(encoding="ascii"))
    identity.pop("journal_key_id")
    identity["schema_version"] = "1.4"
    _write_canonical(identity_path, identity)

    path = _revision_path(attempt, 1)
    value = _read_revision(attempt, 1)
    value.pop("journal_mac")
    value["schema_version"] = "1.4"
    _write_canonical(path, value)

    with pytest.raises((SchedulerStateInvalidError, SchedulerStateContractError)):
        _new_store(state_fixture).load(
            state_fixture.prepared.manifest.preflight_id,
            request_sha256=_REQUEST_SHA256,
        )


def test_journal_mac_keyless_load_succeeds_but_create_and_append_fail(
    state_fixture: StateFixture, tmp_path: Path
) -> None:
    """A key-less config loads hash-chain-only; it cannot create or extend.

    The key-less file is the staged compute-node projection (ADR 0013): it
    keeps the non-secret ``approval_key_id`` but must never carry the key.
    Compute nodes must load the journal to run (the bootstrap reads the
    preflight), but they must never seal new revisions: every append still
    fails closed without the chain key.
    """
    # Service node (key holder) creates the attempt.
    store = _new_store(state_fixture)
    created = store.create_or_load(state_fixture.prepared, request_sha256=_REQUEST_SHA256)

    config_value = json.loads(state_fixture.config_path.read_text(encoding="ascii"))
    config_value.pop("approval_hmac_key")
    keyless_path = tmp_path / "scheduler-config-keyless.json"
    keyless_path.write_text(
        json.dumps(config_value, allow_nan=False, ensure_ascii=True, separators=(",", ":")),
        encoding="ascii",
    )
    keyless_path.chmod(0o600)
    keyless_config = load_trusted_scheduler_config(keyless_path, require_approval_key=False)
    assert keyless_config.contract.approval_hmac_key is None
    keyless_store = state_module.SchedulerPreflightStore(keyless_config, clock=state_fixture.clock)

    # Load succeeds: the unkeyed hash-chain links are verified, MACs are skipped.
    loaded = keyless_store.create_or_load(state_fixture.prepared, request_sha256=_REQUEST_SHA256)
    assert loaded.revision == created.revision
    assert loaded.journal_sha256 == created.journal_sha256
    assert loaded.state == created.state

    # Create of a fresh attempt fails: sealing the chain needs the key.
    # The worker paths bind to the preflight id, so re-derive them too.
    new_id = "preflight-keyless-create"
    expected_manifest, expected_evidence = expected_worker_paths(keyless_config, new_id)
    fresh_manifest = replace(
        state_fixture.prepared.manifest,
        preflight_id=new_id,
        worker=replace(
            state_fixture.prepared.manifest.worker,
            manifest_path=expected_manifest,
            evidence_path=expected_evidence,
        ),
    )
    fresh_prepared = prepare_preflight(fresh_manifest)
    with pytest.raises(SchedulerStateInvalidError) as captured:
        keyless_store.create_or_load(fresh_prepared, request_sha256=_REQUEST_SHA256)
    assert captured.value.reason_code == "SCHEDULER_JOURNAL_KEY_UNAVAILABLE"
    assert not (state_fixture.state_root / _PREFLIGHT_NAMESPACE / new_id).exists()
