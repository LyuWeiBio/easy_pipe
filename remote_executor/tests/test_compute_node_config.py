"""Tests for the key-less compute-node config projection (M7 staging).

The approval HMAC key is a control-plane-only secret: it must never reach a
compute node.  The service node stages a canonical key-less projection of
config-v2 per reserved run; the compute bootstrap loads that projection with
``require_approval_key=False`` and the loader hard-rejects any key-bearing
file on that path.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from bioexec.scheduler_config import (
    SchedulerConfigError,
    parse_scheduler_config,
    render_compute_node_config,
)
from bioexec.scheduler_config_loader import (
    SchedulerConfigLoadError,
    load_trusted_scheduler_config,
    scheduler_config_binding_matches,
)
from bioexec.scheduler_run import (
    COMPUTE_NODE_CONFIG_DIRNAME,
    COMPUTE_NODE_CONFIG_FILENAME,
    SchedulerRunContractError,
    SchedulerRunStore,
    compute_node_config_path,
    stage_compute_node_config,
    verify_scheduler_run_request,
)

from .test_scheduler_config_loader import (
    SchedulerConfigFixture,
)
from .test_scheduler_config_loader import (
    scheduler_config_fixture as scheduler_config_fixture,
)
from .test_scheduler_run import RunFixture
from .test_scheduler_run import run_fixture as run_fixture
from .test_scheduler_state import state_fixture as state_fixture


def _stripped_value(fixture: SchedulerConfigFixture) -> dict[str, Any]:
    value = dict(fixture.value)
    del value["approval_hmac_key"]
    return value


def _write_config(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_render_strips_key_and_keeps_every_binding(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    loaded = load_trusted_scheduler_config(scheduler_config_fixture.config_path)
    payload = render_compute_node_config(loaded.contract)
    value = json.loads(payload.decode("utf-8"))

    assert "approval_hmac_key" not in value
    # Every other top-level field survives the projection.
    assert set(value) == {
        "schema_version",
        "profile_version",
        "profile_id",
        "profile_hash",
        "runtime",
        "scheduler",
        "read_roots",
        "deploy_roots",
        "work_roots",
        "output_roots",
        "cache_roots",
        "state_root",
        "executables",
        "nextflow_version",
        "nextflow_jar",
        "nextflow_jar_sha256",
        "approval_key_id",
        "limits",
    }
    assert value["approval_key_id"] == loaded.contract.approval_key_id
    assert value["profile_id"] == loaded.contract.profile_id
    assert value["state_root"] == loaded.contract.state_root
    assert value["read_roots"] == list(loaded.contract.read_roots)
    assert value["executables"]["compute_bootstrap"] == (
        loaded.contract.executables.as_mapping()["compute_bootstrap"]
    )
    assert value["limits"]["max_request_bytes"] == loaded.contract.limits.max_request_bytes
    assert value["scheduler"]["partition"] == loaded.contract.scheduler.as_mapping()["partition"]
    # The key must not leak through any nested rendering either.
    assert loaded.contract.approval_hmac_key.hex().encode("ascii") not in payload


def test_render_is_deterministic_and_idempotent(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    loaded = load_trusted_scheduler_config(scheduler_config_fixture.config_path)
    first = render_compute_node_config(loaded.contract)
    second = render_compute_node_config(loaded.contract)
    assert first == second

    stripped = load_trusted_scheduler_config(
        _write_stripped(scheduler_config_fixture), require_approval_key=False
    )
    # Rendering an already-stripped contract yields the identical bytes.
    assert render_compute_node_config(stripped.contract) == first


def _write_stripped(fixture: SchedulerConfigFixture) -> Path:
    path = fixture.config_path.with_name("scheduler-config-compute.json")
    _write_config(path, _stripped_value(fixture))
    return path


def test_parse_keyless_contract_requires_explicit_flag(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    stripped = _stripped_value(scheduler_config_fixture)
    with pytest.raises(SchedulerConfigError):
        parse_scheduler_config(stripped)
    contract = parse_scheduler_config(stripped, allow_missing_approval_key=True)
    assert contract.approval_hmac_key is None
    # The flag must not silently accept a key-bearing mapping either.
    with pytest.raises(SchedulerConfigError):
        parse_scheduler_config(
            scheduler_config_fixture.value, allow_missing_approval_key=True
        )


def test_loader_hard_rejects_key_on_compute_node_path(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    with pytest.raises(SchedulerConfigLoadError):
        load_trusted_scheduler_config(
            scheduler_config_fixture.config_path, require_approval_key=False
        )


def test_loader_rejects_keyless_config_on_default_path(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    with pytest.raises(SchedulerConfigLoadError):
        load_trusted_scheduler_config(_write_stripped(scheduler_config_fixture))


def test_loader_accepts_staged_keyless_config(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    loaded = load_trusted_scheduler_config(
        _write_stripped(scheduler_config_fixture), require_approval_key=False
    )
    assert loaded.contract.approval_hmac_key is None
    assert loaded.contract.profile_id == "hpc01-slurm"
    assert set(loaded.executables) == {
        "python",
        "java",
        "nextflow",
        "apptainer",
        "compute_worker",
        "compute_bootstrap",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    }


def test_stage_writes_owner_only_keyless_file(run_fixture: RunFixture) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config

    staged = stage_compute_node_config(config, snapshot.run_id)

    expected = compute_node_config_path(str(config.state_root.path), snapshot.run_id)
    assert str(staged) == expected
    assert staged.name == COMPUTE_NODE_CONFIG_FILENAME
    assert staged.parent.name == COMPUTE_NODE_CONFIG_DIRNAME
    metadata = staged.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()
    payload = staged.read_bytes()
    assert payload == render_compute_node_config(config.contract)
    assert b"approval_hmac_key" not in payload
    assert config.contract.approval_hmac_key.hex().encode("ascii") not in payload


def test_stage_is_idempotent_but_rejects_divergent_content(
    run_fixture: RunFixture,
) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config

    first = stage_compute_node_config(config, snapshot.run_id)
    second = stage_compute_node_config(config, snapshot.run_id)
    assert first == second

    first.write_bytes(b'{"tampered": true}')
    with pytest.raises(SchedulerRunContractError):
        stage_compute_node_config(config, snapshot.run_id)


def test_stage_refuses_keyless_source_config(run_fixture: RunFixture) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config
    staged = stage_compute_node_config(config, snapshot.run_id)
    stripped = load_trusted_scheduler_config(staged, require_approval_key=False)
    # Staging from an already-stripped config is a programmer error: only the
    # full service-node config may stage.
    with pytest.raises(SchedulerRunContractError):
        stage_compute_node_config(stripped, snapshot.run_id)


def test_workload_batch_names_staged_config_never_the_full_config(
    run_fixture: RunFixture,
) -> None:
    from bioexec.scheduler_workload import prepare_scheduler_workload

    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config
    preflight = run_fixture.run_store.load_consumed_preflight(snapshot)
    plan = prepare_scheduler_workload(config, snapshot, preflight)

    staged = compute_node_config_path(str(config.state_root.path), snapshot.run_id)
    assert plan.bootstrap_argv[5] == f"--config={staged}"
    assert str(config.config_file.path).encode("ascii") not in plan.batch_bytes
    assert config.contract.approval_hmac_key.hex().encode("ascii") not in plan.batch_bytes


def test_compute_node_identity_binding_round_trip(run_fixture: RunFixture) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config
    staged = stage_compute_node_config(config, snapshot.run_id)

    compute_config = load_trusted_scheduler_config(staged, require_approval_key=False)
    compute_store = SchedulerRunStore(
        compute_config, clock=run_fixture.state.clock
    )
    recovered = compute_store.load(snapshot.run_id)
    assert recovered.identity_sha256 == snapshot.identity_sha256
    assert scheduler_config_binding_matches(recovered.identity, compute_config)

    # A compute-node config projecting a *different* contract must not bind.
    tampered_value = _stripped_value_from_run_fixture(run_fixture)
    tampered_value["profile_id"] = "attacker-profile"
    tampered_path = staged.with_name("scheduler-tampered.json")
    _write_config(tampered_path, tampered_value)
    tampered = load_trusted_scheduler_config(tampered_path, require_approval_key=False)
    assert not scheduler_config_binding_matches(snapshot.identity, tampered)


def _stripped_value_from_run_fixture(fixture: RunFixture) -> dict[str, Any]:
    config = fixture.state.config
    value = json.loads(render_compute_node_config(config.contract).decode("utf-8"))
    return value


def test_approval_verification_requires_control_plane_key(
    run_fixture: RunFixture,
) -> None:
    snapshot = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    config = run_fixture.state.config
    staged = stage_compute_node_config(config, snapshot.run_id)
    compute_config = load_trusted_scheduler_config(staged, require_approval_key=False)

    with pytest.raises(SchedulerRunContractError):
        verify_scheduler_run_request(
            run_fixture.request,
            compute_config,
            run_fixture.deployment,
            run_fixture.issued,
        )
