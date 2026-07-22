"""Security and recovery tests for the dormant scheduler run bridge."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import bioexec.compute_bootstrap as bootstrap_module
import bioexec.scheduler_state as state_module
from bioexec.scheduler_protocol import (
    SchedulerRequest,
    canonical_hmac_envelope_bytes,
    parse_request,
)
from bioexec.scheduler_run import (
    SCHEDULER_RUN_NAMESPACE,
    SchedulerDeploymentBinding,
    SchedulerDeploymentFile,
    SchedulerRunBusyError,
    SchedulerRunCommitUnknown,
    SchedulerRunConflictError,
    SchedulerRunInvalidError,
    SchedulerRunPreconditionError,
    SchedulerRunSnapshot,
    SchedulerRunStore,
    SchedulerStartPermitError,
    VerifiedSchedulerRunRequest,
    consume_start_permit,
    verify_scheduler_run_request,
)
from bioexec.scheduler_state import (
    SchedulerPreflightStore,
    SchedulerStateBusyError,
    SchedulerStateSnapshot,
)

from .test_scheduler_state import (
    StateFixture,
    _candidate_snapshot,
    _new_store,
)
from .test_scheduler_state import (
    state_fixture as scheduler_state_fixture,
)

state_fixture = scheduler_state_fixture

_RAW_CAPABILITY = "0123456789abcdef" * 4
_ACTOR = "operator-一"
_SIGNATURE_PLACEHOLDER = "f" * 64


@dataclass(frozen=True)
class RunFixture:
    state: StateFixture
    preflight_store: SchedulerPreflightStore
    issued: SchedulerStateSnapshot
    deployment: SchedulerDeploymentBinding
    request: SchedulerRequest
    signature: str
    verified: VerifiedSchedulerRunRequest
    run_store: SchedulerRunStore

    @property
    def run_directory(self) -> Path:
        return self.state.state_root / SCHEDULER_RUN_NAMESPACE / self.verified.run_id


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _deployment(state: StateFixture) -> SchedulerDeploymentBinding:
    deployment_path = Path(state.prepared.manifest.deploy_dir)
    deployment_path.mkdir(mode=0o700)
    contents = {
        "main.nf": b"workflow {}\n",
        "nextflow.config": b"manifest.main {}\n",
    }
    for name, content in contents.items():
        target = deployment_path / name
        target.write_bytes(content)
        target.chmod(0o400)
    deployment_path.chmod(0o500)
    metadata = deployment_path.stat()
    files = tuple(
        SchedulerDeploymentFile(
            path=name,
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
        )
        for name, content in sorted(contents.items())
    )
    bundle_hash = _canonical_hash([item.as_record() for item in files])
    return SchedulerDeploymentBinding(
        deployment_id="deployment-1",
        deployment_dir=str(deployment_path),
        directory_device=metadata.st_dev,
        directory_inode=metadata.st_ino,
        directory_owner=metadata.st_uid,
        directory_group=metadata.st_gid,
        directory_mode=0o500,
        bundle_hash=bundle_hash,
        files=files,
    )


def _approval_artifacts(state: StateFixture) -> dict[str, str]:
    return {
        **dict(state.prepared.manifest.artifact_hashes),
        "validation_report": "a" * 64,
        "test_report": "b" * 64,
        "preflight_report": "d" * 64,
    }


def _signed_request(
    fixture: StateFixture,
    deployment: SchedulerDeploymentBinding,
    *,
    run_id: str = "run-1",
    actor: str = _ACTOR,
    authorization_id: str = "auth-1",
    signature_override: str | None = None,
) -> tuple[SchedulerRequest, str]:
    compatibility_hash = _canonical_hash(
        {
            "bundle_hash": deployment.bundle_hash,
            "execution_profile": fixture.config.contract.profile_hash,
            "project_hash": fixture.prepared.manifest.project_hash,
        }
    )
    payload: dict[str, Any] = {
        "profile_version": "2.0",
        "profile_id": fixture.config.contract.profile_id,
        "profile_hash": fixture.config.contract.profile_hash,
        "scheduler_policy_hash": fixture.config.scheduler_policy_hash,
        "run_id": run_id,
        "preflight_id": fixture.prepared.manifest.preflight_id,
        "preflight_token": _RAW_CAPABILITY,
        "deployment_id": deployment.deployment_id,
        "project_hash": fixture.prepared.manifest.project_hash,
        "bundle_hash": deployment.bundle_hash,
        "approval": {
            "approved": True,
            "authorization_id": authorization_id,
            "actor": actor,
            "approved_at": "2026-07-23T00:00:00Z",
            "artifact_hashes": _approval_artifacts(fixture),
            "bundle_hash": deployment.bundle_hash,
            "compatibility_hash": compatibility_hash,
            "key_id": fixture.config.contract.approval_key_id,
            "signature": _SIGNATURE_PLACEHOLDER,
        },
    }
    envelope = {
        "protocol_version": "2.0",
        "request_id": f"request-{run_id}",
        "operation": "submit",
        "payload": payload,
    }
    unsigned = parse_request(envelope)
    signature = hmac.new(
        fixture.config.contract.approval_hmac_key,
        canonical_hmac_envelope_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    payload["approval"]["signature"] = signature_override or signature
    return parse_request(envelope), signature


@pytest.fixture
def run_fixture(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> RunFixture:
    state_fixture = request.getfixturevalue("state_fixture")
    assert isinstance(state_fixture, StateFixture)
    preflight_store = _new_store(state_fixture)
    candidate = _candidate_snapshot(state_fixture, preflight_store)
    monkeypatch.setattr(
        state_module.secrets,
        "token_hex",
        lambda length: _RAW_CAPABILITY if length == 32 else "",
    )
    issued_response = preflight_store.issue_capability(candidate)
    deployment = _deployment(state_fixture)
    request, signature = _signed_request(state_fixture, deployment)
    verified = verify_scheduler_run_request(
        request,
        state_fixture.config,
        deployment,
        issued_response.snapshot,
    )
    return RunFixture(
        state=state_fixture,
        preflight_store=preflight_store,
        issued=issued_response.snapshot,
        deployment=deployment,
        request=request,
        signature=signature,
        verified=verified,
        run_store=SchedulerRunStore(state_fixture.config, clock=state_fixture.clock),
    )


def _consume_capability(fixture: RunFixture) -> SchedulerStateSnapshot:
    return fixture.preflight_store.consume_capability(
        fixture.issued,
        token=_RAW_CAPABILITY,
        consumed_by=fixture.verified.actor,
        consumer_binding_hash=fixture.verified.consumer_binding_hash,
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


def test_hmac_unicode_actor_and_consumer_binding_happy_path(run_fixture: RunFixture) -> None:
    verified_again = verify_scheduler_run_request(
        run_fixture.request,
        run_fixture.state.config,
        run_fixture.deployment,
        run_fixture.issued,
    )

    assert run_fixture.verified.actor == _ACTOR
    assert run_fixture.verified.consumer_binding_hash == verified_again.consumer_binding_hash
    assert len(run_fixture.verified.consumer_binding_hash) == 64
    assert run_fixture.verified.consumer_binding_hash != run_fixture.verified.request_binding_sha256


def test_wrong_hmac_signature_is_rejected(run_fixture: RunFixture) -> None:
    wrong, _expected = _signed_request(
        run_fixture.state,
        run_fixture.deployment,
        signature_override="e" * 64,
    )

    with pytest.raises(SchedulerRunPreconditionError) as captured:
        verify_scheduler_run_request(
            wrong,
            run_fixture.state.config,
            run_fixture.deployment,
            run_fixture.issued,
        )

    assert captured.value.reason_code == "SCHEDULER_RUN_APPROVAL_INVALID"


def test_reserve_exact_replay_load_and_different_binding_conflict(
    run_fixture: RunFixture,
) -> None:
    first = run_fixture.run_store.reserve(run_fixture.verified)
    repeated = run_fixture.run_store.reserve(run_fixture.verified)
    restarted_store = SchedulerRunStore(run_fixture.state.config)
    restarted = restarted_store.load(run_fixture.verified.run_id)

    assert first.identity_sha256 == repeated.identity_sha256 == restarted.identity_sha256
    assert first.identity == repeated.identity == restarted.identity
    assert restarted.actor == _ACTOR
    assert restarted.consumer_binding_hash == run_fixture.verified.consumer_binding_hash

    changed_request, _signature = _signed_request(
        run_fixture.state,
        run_fixture.deployment,
        actor="operator-二",
        authorization_id="auth-2",
    )
    changed = verify_scheduler_run_request(
        changed_request,
        run_fixture.state.config,
        run_fixture.deployment,
        run_fixture.issued,
    )
    assert changed.consumer_binding_hash != run_fixture.verified.consumer_binding_hash
    with pytest.raises(SchedulerRunConflictError) as captured:
        run_fixture.run_store.reserve(changed)
    assert captured.value.reason_code == "SCHEDULER_RUN_ALREADY_RESERVED"


def test_raw_token_signature_and_key_are_absent_from_identity_and_repr(
    run_fixture: RunFixture,
) -> None:
    snapshot = run_fixture.run_store.reserve(run_fixture.verified)
    identity_path = run_fixture.run_directory / "identity.json"
    raw_identity = identity_path.read_bytes()
    representations = (repr(run_fixture.verified), repr(snapshot))
    key_hex = run_fixture.state.config.contract.approval_hmac_key.hex()

    for secret in (_RAW_CAPABILITY, run_fixture.signature, key_hex):
        assert secret.encode("ascii") not in raw_identity
        assert all(secret not in representation for representation in representations)
    assert "preflight_token" not in snapshot.identity
    assert "signature" not in snapshot.identity


def test_consumption_response_loss_recovers_exact_consumed_preflight(
    run_fixture: RunFixture,
) -> None:
    run_fixture.run_store.reserve(run_fixture.verified)
    committed_but_response_lost = _consume_capability(run_fixture)
    del committed_but_response_lost

    restarted_store = SchedulerRunStore(run_fixture.state.config)
    replayed_run = restarted_store.load(run_fixture.verified.run_id)
    recovered = restarted_store.load_consumed_preflight(replayed_run)
    capability = recovered.state.capability

    assert capability is not None and capability.consumed
    assert capability.consumed_by == _ACTOR
    assert capability.consumer_binding_hash == run_fixture.verified.consumer_binding_hash


def test_run_store_reserves_before_consuming_the_exact_hidden_capability(
    run_fixture: RunFixture,
) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    consumed = run_fixture.run_store.load_consumed_preflight(snapshot)
    capability = consumed.state.capability
    repeated = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    replayed = run_fixture.run_store.load_consumed_preflight(repeated)

    assert capability is not None and capability.consumed
    assert capability.consumed_by == run_fixture.verified.actor
    assert capability.consumer_binding_hash == run_fixture.verified.consumer_binding_hash
    assert replayed.revision == consumed.revision
    assert repeated.identity_sha256 == snapshot.identity_sha256


def test_capability_commit_unknown_recovers_only_after_restart(
    run_fixture: RunFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = SchedulerPreflightStore.consume_capability

    def lose_response(
        store: SchedulerPreflightStore,
        snapshot: SchedulerStateSnapshot,
        *,
        token: str,
        consumed_by: str,
        consumer_binding_hash: str,
    ) -> SchedulerStateSnapshot:
        original(
            store,
            snapshot,
            token=token,
            consumed_by=consumed_by,
            consumer_binding_hash=consumer_binding_hash,
        )
        raise state_module.SchedulerStateCommitUnknown(
            "SCHEDULER_STATE_COMMIT_UNKNOWN",
            "synthetic lost consume response",
        )

    monkeypatch.setattr(SchedulerPreflightStore, "consume_capability", lose_response)
    with pytest.raises(SchedulerRunCommitUnknown) as captured:
        run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    assert captured.value.reason_code == "SCHEDULER_RUN_CAPABILITY_COMMIT_UNKNOWN"

    monkeypatch.setattr(SchedulerPreflightStore, "consume_capability", original)
    restarted = SchedulerRunStore(
        run_fixture.state.config,
        clock=run_fixture.state.clock,
    )
    recovered_run = restarted.reserve_and_consume(run_fixture.verified)
    recovered = restarted.load_consumed_preflight(recovered_run)
    capability = recovered.state.capability
    assert capability is not None and capability.consumed
    assert capability.consumer_binding_hash == run_fixture.verified.consumer_binding_hash


def test_fixed_compute_bootstrap_burns_one_intent_and_never_replays(
    run_fixture: RunFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config
    bootstrap = config.executables["compute_bootstrap"]
    assert bootstrap.sha256 is not None
    invocation = bootstrap_module.parse_bootstrap_argv(
        [
            "--contract-version=1.0",
            f"--config={run_fixture.state.config_path}",
            f"--run-id={snapshot.run_id}",
            f"--identity-sha256={snapshot.identity_sha256}",
            f"--bootstrap-sha256={bootstrap.sha256}",
        ]
    )
    monkeypatch.setattr(bootstrap_module, "_verify_sif_artifacts", lambda _state: None)

    bootstrap_module._run_fixed_bootstrap(
        invocation,
        bootstrap_path=str(bootstrap.path),
        python_path=str(config.executables["python"].path),
    )

    intent = run_fixture.run_directory / "start.intent.json"
    assert intent.is_file()
    assert _RAW_CAPABILITY.encode("ascii") not in intent.read_bytes()
    with pytest.raises(SchedulerRunConflictError) as captured:
        bootstrap_module._run_fixed_bootstrap(
            invocation,
            bootstrap_path=str(bootstrap.path),
            python_path=str(config.executables["python"].path),
        )
    assert captured.value.reason_code == "SCHEDULER_RUN_START_ALREADY_CLAIMED"


def test_compute_bootstrap_checks_every_sif_binding(
    run_fixture: RunFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumed = _consume_capability(run_fixture)
    expected = {
        container.local_path: container.file_sha256
        for container in consumed.state.manifest.containers
    }
    observed: list[str] = []

    def observe(path: str, **_kwargs: Any) -> dict[str, str]:
        observed.append(path)
        return {"sha256": expected[path]}

    monkeypatch.setattr(bootstrap_module, "_observe_regular", observe)
    bootstrap_module._verify_sif_artifacts(consumed.state)
    assert observed == [container.local_path for container in consumed.state.manifest.containers]

    def mismatch(path: str, **_kwargs: Any) -> dict[str, str]:
        return {"sha256": "f" * 64 if path == observed[-1] else expected[path]}

    monkeypatch.setattr(bootstrap_module, "_observe_regular", mismatch)
    with pytest.raises(bootstrap_module.ComputeBootstrapError, match="SIF hash"):
        bootstrap_module._verify_sif_artifacts(consumed.state)


def test_compute_bootstrap_rehashes_the_exact_deployment(
    run_fixture: RunFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_fixture.run_store.reserve(run_fixture.verified)
    consumed = _consume_capability(run_fixture)
    config = run_fixture.state.config
    monkeypatch.setattr(bootstrap_module, "_verify_sif_artifacts", lambda _state: None)

    bootstrap_module.verify_compute_artifacts(
        config,
        run_fixture.deployment,
        consumed,
        bootstrap_path=str(config.executables["compute_bootstrap"].path),
        python_path=str(config.executables["python"].path),
    )

    changed = Path(run_fixture.deployment.deployment_dir) / "main.nf"
    changed.chmod(0o600)
    changed.write_bytes(b"workflow { changed }\n")
    changed.chmod(0o400)
    with pytest.raises(bootstrap_module.ComputeBootstrapError, match="deployment"):
        bootstrap_module.verify_compute_artifacts(
            config,
            run_fixture.deployment,
            consumed,
            bootstrap_path=str(config.executables["compute_bootstrap"].path),
            python_path=str(config.executables["python"].path),
        )


@pytest.mark.parametrize(
    "artifact",
    ["python", "java", "nextflow", "apptainer", "compute_bootstrap", "nextflow_jar"],
)
def test_compute_bootstrap_rehashes_every_fixed_runtime(
    run_fixture: RunFixture,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
) -> None:
    run_fixture.run_store.reserve(run_fixture.verified)
    consumed = _consume_capability(run_fixture)
    config = run_fixture.state.config
    monkeypatch.setattr(bootstrap_module, "_verify_sif_artifacts", lambda _state: None)
    target = (
        config.nextflow_jar.path
        if artifact == "nextflow_jar"
        else config.executables[artifact].path
    )
    target.chmod(0o700)
    target.write_bytes(b"changed after trusted config load\n")
    target.chmod(0o444 if artifact == "nextflow_jar" else 0o755)

    with pytest.raises(bootstrap_module.ComputeBootstrapError, match="runtime"):
        bootstrap_module.verify_compute_artifacts(
            config,
            run_fixture.deployment,
            consumed,
            bootstrap_path=str(config.executables["compute_bootstrap"].path),
            python_path=str(config.executables["python"].path),
        )


def test_claim_start_verifier_failure_leaves_no_intent(run_fixture: RunFixture) -> None:
    snapshot = run_fixture.run_store.reserve(run_fixture.verified)
    consumed = _consume_capability(run_fixture)

    def failed_verifier() -> None:
        raise RuntimeError("synthetic bootstrap failure")

    with (
        pytest.raises(RuntimeError, match="synthetic bootstrap failure"),
        run_fixture.run_store.claim_start(snapshot, consumed, failed_verifier),
    ):
        pytest.fail("a failed bootstrap verifier must not yield a permit")

    assert not (run_fixture.run_directory / "start.intent.json").exists()
    with run_fixture.run_store.claim_start(snapshot, consumed, lambda: None) as permit:
        consume_start_permit(permit, snapshot)


def test_start_permit_is_one_use_and_restart_never_reissues(run_fixture: RunFixture) -> None:
    snapshot = run_fixture.run_store.reserve(run_fixture.verified)
    consumed = _consume_capability(run_fixture)

    with run_fixture.run_store.claim_start(snapshot, consumed, lambda: None) as permit:
        assert _RAW_CAPABILITY not in repr(permit)
        consume_start_permit(permit, snapshot)
        with pytest.raises(SchedulerStartPermitError):
            consume_start_permit(permit, snapshot)

    restarted_store = SchedulerRunStore(run_fixture.state.config)
    restarted = restarted_store.load(snapshot.run_id)
    recovered_preflight = restarted_store.load_consumed_preflight(restarted)
    with (
        pytest.raises(SchedulerRunConflictError) as captured,
        restarted_store.claim_start(restarted, recovered_preflight, lambda: None),
    ):
        pytest.fail("restart must not recreate a start permit")
    assert captured.value.reason_code == "SCHEDULER_RUN_START_ALREADY_CLAIMED"


def test_start_permit_rejects_another_thread(run_fixture: RunFixture) -> None:
    snapshot = run_fixture.run_store.reserve(run_fixture.verified)
    consumed = _consume_capability(run_fixture)

    with run_fixture.run_store.claim_start(snapshot, consumed, lambda: None) as permit:
        with ThreadPoolExecutor(max_workers=1) as executor:
            failure = executor.submit(_permit_failure_code, permit, snapshot).result(timeout=2)
        assert failure == "SCHEDULER_RUN_START_PERMIT_INVALID"
        consume_start_permit(permit, snapshot)


def _permit_failure_code(permit: Any, snapshot: SchedulerRunSnapshot) -> str | None:
    try:
        consume_start_permit(permit, snapshot)
    except SchedulerStartPermitError as exc:
        return exc.reason_code
    return None


@pytest.mark.parametrize("partial", [True, False])
def test_partial_or_semantically_tampered_identity_fails_closed(
    run_fixture: RunFixture,
    partial: bool,
) -> None:
    run_fixture.run_store.reserve(run_fixture.verified)
    identity_path = run_fixture.run_directory / "identity.json"
    if partial:
        identity_path.write_bytes(b'{"schema_version":"1.0"')
        identity_path.chmod(0o600)
    else:
        identity = json.loads(identity_path.read_text(encoding="ascii"))
        identity["actor"] = "operator-篡改"
        _write_canonical(identity_path, identity)

    with pytest.raises(SchedulerRunInvalidError):
        SchedulerRunStore(run_fixture.state.config).load(run_fixture.verified.run_id)


def test_concurrent_start_claim_has_exactly_one_permit(run_fixture: RunFixture) -> None:
    run_fixture.run_store.reserve(run_fixture.verified)
    _consume_capability(run_fixture)
    stores = (
        SchedulerRunStore(run_fixture.state.config),
        SchedulerRunStore(run_fixture.state.config),
    )
    snapshots = tuple(store.load(run_fixture.verified.run_id) for store in stores)
    preflights = tuple(
        stores[index].load_consumed_preflight(snapshots[index]) for index in range(len(stores))
    )
    barrier = threading.Barrier(2)

    def claim(index: int) -> str:
        barrier.wait(timeout=2)
        try:
            with stores[index].claim_start(
                snapshots[index], preflights[index], lambda: None
            ) as permit:
                consume_start_permit(permit, snapshots[index])
        except (SchedulerRunBusyError, SchedulerRunConflictError, SchedulerStateBusyError):
            return "rejected"
        return "started"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, range(2)))

    assert results.count("started") == 1
    assert results.count("rejected") == 1
    assert (run_fixture.run_directory / "start.intent.json").is_file()
