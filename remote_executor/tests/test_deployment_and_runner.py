from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import stat
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bioexec.runner as runner_module
from bioexec.commands import CommandResult, run_to_logs
from bioexec.config import AgentConfig, ExecutableIdentity
from bioexec.deployment import deploy_bundle, verify_deployment
from bioexec.errors import AgentFailure
from bioexec.main import serve_once
from bioexec.preflight import run_preflight
from bioexec.runner import (
    _fixed_nextflow_invocation,
    _normalize_process_return_code,
    _write_network_overlay,
    handle_run_operation,
)
from bioexec.state import StateStore

from .conftest import (
    bundle_hash,
    canonical_hash,
    core_hashes,
    deployment_contents,
    deployment_files,
    project_hash,
)


def _preflight_and_deploy(
    config: AgentConfig,
    make_preflight_payload: Any,
) -> tuple[StateStore, dict[str, Any], dict[str, Any], dict[str, bytes]]:
    state = StateStore(config.state_root)
    result, record = run_preflight(make_preflight_payload(), config, state=state)
    assert record is not None
    state.create("preflights", record["preflight_id"], record)
    contents = deployment_contents()
    deployment_payload = {
        "deployment_id": "deployment-1",
        "preflight_id": record["preflight_id"],
        "profile_id": config.profile_id,
        "profile_hash": config.profile_hash,
        "project_hash": project_hash(config),
        "bundle_hash": bundle_hash(contents),
        "deployment_dir": record["deploy_dir"],
        "files": deployment_files(contents),
    }
    deployed = deploy_bundle(deployment_payload, config, state)
    assert deployed == {
        "deployment_id": "deployment-1",
        "bundle_hash": bundle_hash(contents),
        "file_count": len(contents),
        "status": "deployed",
    }
    return state, result, record, contents


def _approval(
    config: AgentConfig,
    bundle: str,
    *,
    preflight_report: str = "8" * 64,
) -> dict[str, Any]:
    hashes = {
        **core_hashes(config),
        "validation_report": "6" * 64,
        "test_report": "7" * 64,
        "preflight_report": preflight_report,
    }
    compatibility = canonical_hash(
        {
            "bundle_hash": bundle,
            "execution_profile": config.profile_hash,
            "project_hash": project_hash(config),
        }
    )
    return {
        "approved": True,
        "authorization_id": "auth-0123456789abcdef0123456789abcdef",
        "actor": "Synthetic Test Operator",
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "artifact_hashes": hashes,
        "bundle_hash": bundle,
        "compatibility_hash": compatibility,
        "key_id": config.approval_key_id,
        "signature": "0" * 64,
    }


def _sign_payload(config: AgentConfig, operation: str, payload: dict[str, Any]) -> None:
    approval = dict(payload["approval"])
    approval.pop("signature", None)
    unsigned = {**payload, "approval": approval}
    material = json.dumps(
        {"protocol_version": "1.0", "operation": operation, "payload": unsigned},
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    payload["approval"]["signature"] = hmac.new(
        config.approval_hmac_key,
        material,
        hashlib.sha256,
    ).hexdigest()


def _submit_payload(
    config: AgentConfig,
    preflight_result: dict[str, Any],
    bundle: str,
    *,
    run_id: str = "run-1",
) -> dict[str, Any]:
    payload = {
        "run_id": run_id,
        "preflight_id": preflight_result["preflight_id"],
        "preflight_token": preflight_result["preflight_token"],
        "deployment_id": "deployment-1",
        "profile_id": config.profile_id,
        "profile_hash": config.profile_hash,
        "project_hash": project_hash(config),
        "bundle_hash": bundle,
        "approval": _approval(config, bundle),
    }
    _sign_payload(config, "submit", payload)
    return payload


def _status_payload(config: AgentConfig, bundle: str, run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "profile_id": config.profile_id,
        "profile_hash": config.profile_hash,
        "project_hash": project_hash(config),
        "bundle_hash": bundle,
    }


def _abandon_payload(
    config: AgentConfig,
    bundle: str,
    *,
    run_id: str = "run-1",
    submitted_at: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "run_id": run_id,
        "profile_id": config.profile_id,
        "profile_hash": config.profile_hash,
        "project_hash": project_hash(config),
        "bundle_hash": bundle,
        "deployment_id": "deployment-1",
        "resume_run_id": None,
        "submitted_at": submitted_at or datetime.now(timezone.utc).isoformat(),
        "approval": {
            "key_id": config.approval_key_id,
            "signature": "0" * 64,
        },
    }
    _sign_payload(config, "abandon", payload)
    return payload


def _wait_terminal(
    state: StateStore,
    config: AgentConfig,
    bundle: str,
    run_id: str,
) -> dict[str, Any]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = handle_run_operation(
            "status", _status_payload(config, bundle, run_id), config, state
        )
        if result["status"] in {"succeeded", "failed"}:
            return result
        time.sleep(0.02)
    raise AssertionError("synthetic run did not reach a terminal state")


def test_deployment_is_create_only_allowlisted_and_verifiable(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, _result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    deployment = state.read("deployments", "deployment-1")
    verify_deployment(deployment, agent_config)
    root = Path(record["deploy_dir"])
    assert {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()} == set(
        contents
    )
    assert not any("tests" in path.parts for path in root.rglob("*"))
    assert stat.S_IMODE(root.stat().st_mode) == 0o500
    assert all(
        stat.S_IMODE(path.stat().st_mode) == (0o500 if path.is_dir() else 0o400)
        for path in root.rglob("*")
    )


def test_deployment_rejects_declared_bundle_mismatch_without_creating_target(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state = StateStore(agent_config.state_root)
    result, record = run_preflight(make_preflight_payload(), agent_config, state=state)
    assert result["status"] == "passed" and record is not None
    state.create("preflights", record["preflight_id"], record)
    contents = deployment_contents()
    payload = {
        "deployment_id": "deployment-1",
        "preflight_id": record["preflight_id"],
        "profile_id": agent_config.profile_id,
        "profile_hash": agent_config.profile_hash,
        "project_hash": project_hash(agent_config),
        "bundle_hash": "0" * 64,
        "deployment_dir": record["deploy_dir"],
        "files": deployment_files(contents),
    }
    with pytest.raises(AgentFailure) as raised:
        deploy_bundle(payload, agent_config, state)
    assert raised.value.code == "BUNDLE_HASH_MISMATCH"
    assert not Path(record["deploy_dir"]).exists()


def test_completed_deployment_replay_is_verified_and_idempotent(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, _result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    payload = {
        "deployment_id": "deployment-1",
        "preflight_id": record["preflight_id"],
        "profile_id": agent_config.profile_id,
        "profile_hash": agent_config.profile_hash,
        "project_hash": project_hash(agent_config),
        "bundle_hash": bundle_hash(contents),
        "deployment_dir": record["deploy_dir"],
        "files": deployment_files(contents),
    }

    assert deploy_bundle(payload, agent_config, state) == {
        "deployment_id": "deployment-1",
        "bundle_hash": bundle_hash(contents),
        "file_count": len(contents),
        "status": "deployed",
    }


def test_deployment_replay_rejects_changed_or_incomplete_binding(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, _result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    payload = {
        "deployment_id": "deployment-1",
        "preflight_id": record["preflight_id"],
        "profile_id": agent_config.profile_id,
        "profile_hash": agent_config.profile_hash,
        "project_hash": "f" * 64,
        "bundle_hash": bundle_hash(contents),
        "deployment_dir": record["deploy_dir"],
        "files": deployment_files(contents),
    }
    with pytest.raises(AgentFailure) as changed:
        deploy_bundle(payload, agent_config, state)
    assert changed.value.code == "DEPLOYMENT_ID_CONFLICT"

    complete = state.read("deployments", "deployment-1")
    state.replace("deployments", "deployment-1", {**complete, "status": "reserved"})
    payload["project_hash"] = project_hash(agent_config)
    with pytest.raises(AgentFailure) as incomplete:
        deploy_bundle(payload, agent_config, state)
    assert incomplete.value.code == "DEPLOYMENT_ID_CONFLICT"


@pytest.mark.parametrize("forbidden", ["tests/evil.nf", "raw/sample.fastq.gz"])
def test_deployment_rejects_tests_and_raw_formats(
    forbidden: str,
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state = StateStore(agent_config.state_root)
    _result, record = run_preflight(make_preflight_payload(), agent_config, state=state)
    assert record is not None
    state.create("preflights", record["preflight_id"], record)
    contents = {**deployment_contents(), forbidden: b"forbidden\n"}
    payload = {
        "deployment_id": "deployment-1",
        "preflight_id": record["preflight_id"],
        "profile_id": agent_config.profile_id,
        "profile_hash": agent_config.profile_hash,
        "project_hash": project_hash(agent_config),
        "bundle_hash": bundle_hash(contents),
        "deployment_dir": record["deploy_dir"],
        "files": deployment_files(contents),
    }
    with pytest.raises(AgentFailure):
        deploy_bundle(payload, agent_config, state)
    assert not Path(record["deploy_dir"]).exists()


def test_deployment_tamper_is_detected_before_run(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    main = Path(record["deploy_dir"]) / "main.nf"
    main.chmod(0o600)
    main.write_text("tampered\n", encoding="utf-8")
    payload = _submit_payload(agent_config, result, bundle_hash(contents))
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation("submit", payload, agent_config, state)
    assert raised.value.code == "DEPLOYMENT_CONTENT_CHANGED"
    assert state.read("preflights", result["preflight_id"])["consumed"] is False


def test_submit_requires_explicit_exact_approval(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    payload = _submit_payload(agent_config, result, bundle_hash(contents))
    payload["approval"] = {**payload["approval"], "approved": False}
    _sign_payload(agent_config, "submit", payload)
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation("submit", payload, agent_config, state)
    assert raised.value.code == "APPROVAL_REQUIRED"
    assert state.read("preflights", result["preflight_id"])["consumed"] is False


def test_submit_rejects_forged_controller_attestation_before_state_or_token_use(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    payload = _submit_payload(agent_config, result, bundle_hash(contents))
    payload["approval"]["actor"] = "Forged Operator"
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation("submit", payload, agent_config, state)
    assert raised.value.code == "APPROVAL_ATTESTATION_INVALID"
    assert state.read("preflights", result["preflight_id"])["consumed"] is False
    with pytest.raises(AgentFailure) as absent:
        state.read("runs", "run-1")
    assert absent.value.code == "STATE_NOT_FOUND"


def test_submit_runs_fixed_offline_nextflow_and_status_discloses_no_paths(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    digest = bundle_hash(contents)
    response = handle_run_operation(
        "submit", _submit_payload(agent_config, result, digest), agent_config, state
    )
    assert {
        key: response[key]
        for key in {
            "run_id",
            "status",
            "remote_work_dir",
            "result_dir",
        }
    } == {
        "run_id": "run-1",
        "status": "submitted",
        "remote_work_dir": record["work_dir"],
        "result_dir": record["output_dir"],
    }
    assert response["command_hash"] and response["environment_hash"]
    terminal = _wait_terminal(state, agent_config, digest, "run-1")
    assert terminal == {
        "run_id": "run-1",
        "status": "succeeded",
        "return_code": 0,
        "command_hash": response["command_hash"],
        "environment_hash": response["environment_hash"],
    }
    run = state.read("runs", "run-1")
    run_dir = Path(run["run_directory"])
    overlay = (run_dir / "network.config").read_text(encoding="ascii")
    stdout = (run_dir / "stdout.log").read_text(encoding="utf-8")
    assert "--network none" in overlay
    assert "--pull=never" in overlay
    assert overlay.startswith(f"includeConfig '{record['deploy_dir']}/nextflow.config'\n")
    assert stdout.startswith("-C ")
    assert "-profile local" in stdout
    assert "--output_dir" in stdout
    assert Path(record["work_dir"]).is_dir()
    assert Path(record["output_dir"]).is_dir()


def test_network_overlay_includes_reviewed_project_before_final_engine_policy(
    tmp_path: Path,
) -> None:
    docker_dir = tmp_path / "docker-run"
    docker_dir.mkdir()
    deployment = "/deploy/path-with-'quote"
    docker_containers = [
        {"name": "fastqc", "local_path": None},
        {"name": "multiqc", "local_path": None},
    ]
    docker = _write_network_overlay(docker_dir, "docker", deployment, docker_containers).read_text()
    assert docker.splitlines()[0] == "includeConfig '/deploy/path-with-\\'quote/nextflow.config'"
    assert docker.index("includeConfig") < docker.index("process.executor")
    assert "docker.enabled = true" in docker
    assert "docker.runOptions = '--network none --pull=never'" in docker
    assert "wave.enabled = false" in docker
    assert ".sif" not in docker

    apptainer_dir = tmp_path / "apptainer-run"
    apptainer_dir.mkdir()
    apptainer_containers = [
        {"name": "fastqc", "local_path": "/cache/fastqc.sif"},
        {"name": "fastp", "local_path": "/cache/fastp.sif"},
        {"name": "multiqc", "local_path": "/cache/multiqc.sif"},
    ]
    apptainer = _write_network_overlay(
        apptainer_dir,
        "apptainer",
        "/deploy/project",
        apptainer_containers,
    ).read_text()
    assert apptainer.index("includeConfig") < apptainer.index("process.executor")
    assert "docker.enabled = false" in apptainer
    assert "apptainer.enabled = true" in apptainer
    assert (
        "apptainer.runOptions = '--containall --no-home --cleanenv --net --network none'"
        in apptainer
    )
    assert "withLabel: 'fastqc_raw'" in apptainer
    assert "withLabel: 'fastqc_post_trim'" in apptainer
    assert "withLabel: 'fastp'" in apptainer
    assert "withLabel: 'multiqc'" in apptainer
    for local_sif in (
        "/cache/fastqc.sif",
        "/cache/fastp.sif",
        "/cache/multiqc.sif",
    ):
        assert local_sif in apptainer
    assert "quay.io" not in apptainer

    unicode_dir = tmp_path / "unicode-run"
    unicode_dir.mkdir()
    unicode_overlay = _write_network_overlay(
        unicode_dir,
        "apptainer",
        "/部署/项目",
        [
            {"name": "fastqc", "local_path": "/缓存/fastqc镜像.sif"},
            {"name": "multiqc", "local_path": "/缓存/multiqc镜像.sif"},
        ],
    ).read_text(encoding="utf-8")
    assert "includeConfig '/部署/项目/nextflow.config'" in unicode_overlay
    assert "/缓存/fastqc镜像.sif" in unicode_overlay


def test_preflight_token_is_one_shot(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    digest = bundle_hash(contents)
    handle_run_operation(
        "submit", _submit_payload(agent_config, result, digest), agent_config, state
    )
    _wait_terminal(state, agent_config, digest, "run-1")
    replay = _submit_payload(agent_config, result, digest, run_id="run-2")
    _sign_payload(agent_config, "submit", replay)
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation("submit", replay, agent_config, state)
    assert raised.value.code == "PREFLIGHT_STALE_OR_CONSUMED"


def test_input_replacement_after_preflight_blocks_submit_without_consuming_token(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    raw = Path(record["input_records"][0]["path"])
    raw.write_bytes(b"changed synthetic bytes\n")
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation(
            "submit",
            _submit_payload(agent_config, result, bundle_hash(contents)),
            agent_config,
            state,
        )
    assert raised.value.code == "INPUT_CHANGED_AFTER_PREFLIGHT"
    assert state.read("preflights", result["preflight_id"])["consumed"] is False


def test_existing_output_blocks_initial_submit(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    Path(record["output_dir"]).mkdir()
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation(
            "submit",
            _submit_payload(agent_config, result, bundle_hash(contents)),
            agent_config,
            state,
        )
    assert raised.value.code == "TARGET_ALREADY_EXISTS"
    assert state.read("preflights", result["preflight_id"])["consumed"] is False


def test_status_requires_exact_immutable_bindings(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    digest = bundle_hash(contents)
    handle_run_operation(
        "submit", _submit_payload(agent_config, result, digest), agent_config, state
    )
    _wait_terminal(state, agent_config, digest, "run-1")
    wrong = {**_status_payload(agent_config, digest, "run-1"), "project_hash": "0" * 64}
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation("status", wrong, agent_config, state)
    assert raised.value.code == "RUN_NOT_FOUND"


def test_compatible_resume_reuses_paths_and_adds_only_fixed_resume_flag(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, first_result, first_record, contents = _preflight_and_deploy(
        agent_config, make_preflight_payload
    )
    digest = bundle_hash(contents)
    handle_run_operation(
        "submit",
        _submit_payload(agent_config, first_result, digest),
        agent_config,
        state,
    )
    assert _wait_terminal(state, agent_config, digest, "run-1")["status"] == "succeeded"
    second_payload = make_preflight_payload(
        preflight_id="preflight-2",
        resume_run_id="run-1",
        deploy_dir=first_record["deploy_dir"],
        work_dir=first_record["work_dir"],
        output_dir=first_record["output_dir"],
    )
    second_result, second_record = run_preflight(second_payload, agent_config, state=state)
    assert second_record is not None
    state.create("preflights", "preflight-2", second_record)
    request = {
        **_submit_payload(agent_config, second_result, digest, run_id="run-2"),
        "resume_run_id": "run-1",
    }
    request["approval"] = _approval(agent_config, digest, preflight_report="9" * 64)
    _sign_payload(agent_config, "resume", request)
    response = handle_run_operation("resume", request, agent_config, state)
    assert response["remote_work_dir"] == first_record["work_dir"]
    assert response["result_dir"] == first_record["output_dir"]
    assert _wait_terminal(state, agent_config, digest, "run-2")["status"] == "succeeded"
    second_run = state.read("runs", "run-2")
    stdout = (Path(second_run["run_directory"]) / "stdout.log").read_text()
    assert stdout.rstrip().endswith("-resume")


def test_resume_preflight_rejects_path_change_as_failed_report(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, first_result, first_record, contents = _preflight_and_deploy(
        agent_config, make_preflight_payload
    )
    digest = bundle_hash(contents)
    handle_run_operation(
        "submit", _submit_payload(agent_config, first_result, digest), agent_config, state
    )
    _wait_terminal(state, agent_config, digest, "run-1")
    changed = agent_config.work_roots[0].path / "different-work"
    result, record = run_preflight(
        make_preflight_payload(
            preflight_id="preflight-2",
            resume_run_id="run-1",
            deploy_dir=first_record["deploy_dir"],
            work_dir=str(changed),
            output_dir=first_record["output_dir"],
        ),
        agent_config,
        state=state,
    )
    assert result["status"] == "failed"
    assert result["preflight_token"] is None
    assert record is None
    mapping = {check["name"]: check for check in result["checks"]}
    assert mapping["path_mapping"]["code"] == "RESUME_PREFLIGHT_MISMATCH"


def test_missing_status_is_sanitized_as_run_not_found(agent_config: AgentConfig) -> None:
    state = StateStore(agent_config.state_root)
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation(
            "status",
            _status_payload(agent_config, "b" * 64, "run-missing"),
            agent_config,
            state,
        )
    assert raised.value.code == "RUN_NOT_FOUND"
    assert raised.value.return_code.value == 21


def test_signed_abandon_tombstone_is_idempotent_and_blocks_late_submit(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    digest = bundle_hash(contents)
    abandon = _abandon_payload(agent_config, digest)
    expected = {"run_id": "run-1", "status": "abandoned"}
    request = {
        "protocol_version": "1.0",
        "request_id": "abandon-1",
        "operation": "abandon",
        "payload": abandon,
    }
    frame = json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n"
    first = serve_once(io.BytesIO(frame), agent_config)
    repeated = serve_once(io.BytesIO(frame), agent_config)
    assert first["success"] is True and first["result"] == expected
    assert repeated["success"] is True and repeated["result"] == expected

    with pytest.raises(AgentFailure) as late:
        handle_run_operation(
            "submit",
            _submit_payload(agent_config, result, digest),
            agent_config,
            state,
        )
    assert late.value.code == "STATE_ALREADY_EXISTS"
    assert state.read("runs", "run-1")["status"] == "abandoned"
    assert state.read("preflights", result["preflight_id"])["consumed"] is False
    assert not Path(record["work_dir"]).exists()
    assert not Path(record["output_dir"]).exists()


@pytest.mark.skipif(sys.version_info < (3, 11), reason="controller requires Python 3.11+")
def test_controller_signer_abandon_envelope_reaches_real_service_entrypoint(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    from biopipe.execution.signing import sign_run_payload

    key_file = tmp_path / "controller-hmac.key"
    key_file.write_text("d" * 64 + "\n", encoding="ascii")
    key_file.chmod(0o600)
    profile = SimpleNamespace(
        approval_signer=SimpleNamespace(
            key_id=agent_config.approval_key_id,
            key_file=str(key_file),
        )
    )
    unsigned: dict[str, Any] = {
        "run_id": "run-controller-signed",
        "profile_id": agent_config.profile_id,
        "profile_hash": agent_config.profile_hash,
        "project_hash": project_hash(agent_config),
        "bundle_hash": "b" * 64,
        "deployment_id": "deployment-controller",
        "resume_run_id": None,
        "submitted_at": "2026-07-18T00:00:00Z",
        "approval": {},
    }
    signed = sign_run_payload(profile, "abandon", unsigned)  # type: ignore[arg-type]
    request = {
        "protocol_version": "1.0",
        "request_id": "controller-abandon-1",
        "operation": "abandon",
        "payload": signed,
    }
    frame = json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n"

    response = serve_once(io.BytesIO(frame), agent_config)
    assert response["success"] is True
    assert response["result"] == {
        "run_id": "run-controller-signed",
        "status": "abandoned",
    }
    assert (
        StateStore(agent_config.state_root).read("runs", "run-controller-signed")["status"]
        == "abandoned"
    )


def test_abandon_rejects_forgery_changed_replay_and_existing_run(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    digest = bundle_hash(contents)
    forged = _abandon_payload(agent_config, digest, run_id="run-forged")
    forged["submitted_at"] = datetime.now(timezone.utc).isoformat()
    with pytest.raises(AgentFailure) as unauthenticated:
        handle_run_operation("abandon", forged, agent_config, state)
    assert unauthenticated.value.code == "APPROVAL_ATTESTATION_INVALID"
    with pytest.raises(AgentFailure):
        state.read("runs", "run-forged")

    original = _abandon_payload(agent_config, digest, run_id="run-abandoned")
    handle_run_operation("abandon", original, agent_config, state)
    changed = _abandon_payload(
        agent_config,
        digest,
        run_id="run-abandoned",
        submitted_at="2026-01-01T00:00:00Z",
    )
    with pytest.raises(AgentFailure) as mismatch:
        handle_run_operation("abandon", changed, agent_config, state)
    assert mismatch.value.code == "RUN_ALREADY_EXISTS"

    handle_run_operation(
        "submit",
        _submit_payload(agent_config, result, digest),
        agent_config,
        state,
    )
    with pytest.raises(AgentFailure) as existing:
        handle_run_operation(
            "abandon",
            _abandon_payload(agent_config, digest),
            agent_config,
            state,
        )
    assert existing.value.code == "RUN_ALREADY_EXISTS"


def test_resume_preflight_rejects_replaced_private_directory_identity(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    digest = bundle_hash(contents)
    handle_run_operation(
        "submit", _submit_payload(agent_config, result, digest), agent_config, state
    )
    _wait_terminal(state, agent_config, digest, "run-1")
    work = Path(record["work_dir"])
    work.rename(work.with_name("work-original"))
    work.mkdir(mode=0o700)

    resume, resume_record = run_preflight(
        make_preflight_payload(
            preflight_id="preflight-2",
            resume_run_id="run-1",
            deploy_dir=record["deploy_dir"],
            work_dir=record["work_dir"],
            output_dir=record["output_dir"],
        ),
        agent_config,
        state=state,
    )
    assert resume_record is None
    assert resume["status"] == "failed"
    checks = {item["name"]: item for item in resume["checks"]}
    assert checks["path_mapping"]["code"] == "RESUME_PREFLIGHT_MISMATCH"


def test_job_lease_survives_supervisor_side_close_until_child_exits(
    agent_config: AgentConfig,
) -> None:
    state = StateStore(agent_config.state_root)
    run_id = "run-lease-child"
    run_directory = state.create_run_directory(run_id)
    state.create_supervisor_lease(run_id)
    lease_fd = state.acquire_supervisor_lease(run_id)
    digest = "b" * 64
    command_hash = "1" * 64
    environment_hash = "2" * 64
    state.create(
        "runs",
        run_id,
        {
            "run_id": run_id,
            "profile_id": agent_config.profile_id,
            "profile_hash": agent_config.profile_hash,
            "project_hash": project_hash(agent_config),
            "bundle_hash": digest,
            "status": "running",
            "return_code": None,
            "command_hash": command_hash,
            "environment_hash": environment_hash,
            "updated_at": int(time.time()),
        },
    )
    marker = run_directory / "job-ready"
    release = run_directory / "release-job"
    errors: list[Exception] = []

    def run_child() -> None:
        try:
            run_to_logs(
                (
                    "/bin/sh",
                    "-c",
                    ': > "$1"; while [ ! -e "$2" ]; do /bin/sleep 0.01; done',
                    "bioexec-test",
                    str(marker),
                    str(release),
                ),
                cwd=run_directory,
                env={"PATH": "/bin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
                timeout_seconds=5,
                stdout_path=run_directory / "stdout.log",
                stderr_path=run_directory / "stderr.log",
                job_lease_fd=lease_fd,
            )
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=run_child)
    worker.start()
    lease_closed = False
    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.01)
        assert marker.exists()

        os.close(lease_fd)
        lease_closed = True
        while_child_alive = handle_run_operation(
            "status", _status_payload(agent_config, digest, run_id), agent_config, state
        )
        assert while_child_alive == {
            "run_id": run_id,
            "status": "running",
            "return_code": None,
            "command_hash": command_hash,
            "environment_hash": environment_hash,
        }
    finally:
        if not lease_closed:
            os.close(lease_fd)
        release.touch()
        worker.join(timeout=6)

    assert not worker.is_alive()
    assert not errors
    terminal = handle_run_operation(
        "status", _status_payload(agent_config, digest, run_id), agent_config, state
    )
    assert terminal["status"] == "failed"
    assert terminal["return_code"] == 44
    assert state.read("runs", run_id)["failure_code"] == "SUPERVISOR_ABANDONED"


def test_executable_inode_swap_after_preflight_is_blocked_before_nextflow(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)
    nextflow = agent_config.executables.nextflow
    nextflow.rename(nextflow.with_name("nextflow.reviewed"))
    nextflow.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    nextflow.chmod(0o755)
    digest = bundle_hash(contents)
    submitted = handle_run_operation(
        "submit", _submit_payload(agent_config, result, digest), agent_config, state
    )

    terminal = _wait_terminal(state, agent_config, digest, "run-1")
    assert terminal["status"] == "failed"
    assert terminal["return_code"] == 44
    assert terminal["command_hash"] == submitted["command_hash"]


def test_fixed_environment_prioritizes_reviewed_runtime_and_isolates_client_state(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
    tmp_path: Path,
) -> None:
    runtime_directory = tmp_path / "reviewed-runtime"
    runtime_directory.mkdir(mode=0o700)
    docker = runtime_directory / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    metadata = docker.stat()
    identity = ExecutableIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )
    config = replace(
        agent_config,
        executables=replace(
            agent_config.executables,
            docker=docker,
            docker_identity=identity,
        ),
    )
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    isolation: dict[str, Path] = {}
    for name in (
        "client-home",
        "docker-config",
        "apptainer-config",
        "nxf-home",
        "tmp",
    ):
        path = run_directory / name
        path.mkdir(mode=0o700)
        isolation[name] = path
    _argv, environment = _fixed_nextflow_invocation(
        make_preflight_payload(),
        config,
        run_directory,
        run_directory / "network.config",
        resume=False,
        client_isolation=isolation,
    )

    assert environment["PATH"].split(os.pathsep)[0] == str(runtime_directory)
    assert environment["JAVA_CMD"] == str(agent_config.executables.java)
    assert environment["HOME"] == str(isolation["client-home"])
    assert environment["DOCKER_CONFIG"] == str(isolation["docker-config"])
    assert environment["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert environment["NXF_BIN"] == str(agent_config.nextflow_jar)
    assert environment["NXF_VER"] == agent_config.nextflow_version
    assert environment["TMPDIR"] == str(isolation["tmp"])
    assert all(".config/bioexec" not in value for value in environment.values())


def test_signal_return_code_is_normalized_and_persisted(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, result, _record, contents = _preflight_and_deploy(agent_config, make_preflight_payload)

    def signal_result(argv: Any, **_kwargs: Any) -> CommandResult:
        return CommandResult(tuple(argv), -9, "", "")

    monkeypatch.setattr(runner_module, "run_to_logs", signal_result)
    digest = bundle_hash(contents)
    handle_run_operation(
        "submit", _submit_payload(agent_config, result, digest), agent_config, state
    )
    terminal = _wait_terminal(state, agent_config, digest, "run-1")
    assert terminal["status"] == "failed"
    assert terminal["return_code"] == 137
    assert _normalize_process_return_code(-9) == 137


@pytest.mark.parametrize(
    ("status", "return_code", "command_hash"),
    [
        ("completed", None, "1" * 64),
        ("failed", 0, "1" * 64),
        ("failed", -9, "1" * 64),
        ("failed", 44, None),
    ],
)
def test_status_rejects_corrupt_terminal_state(
    status: str,
    return_code: int | None,
    command_hash: str | None,
    agent_config: AgentConfig,
) -> None:
    state = StateStore(agent_config.state_root)
    run_id = f"run-corrupt-{status}-{str(return_code).replace('-', 'n')}-{command_hash is None}"
    state.create(
        "runs",
        run_id,
        {
            "run_id": run_id,
            "profile_id": agent_config.profile_id,
            "profile_hash": agent_config.profile_hash,
            "project_hash": project_hash(agent_config),
            "bundle_hash": "b" * 64,
            "status": status,
            "return_code": return_code,
            "command_hash": command_hash,
            "environment_hash": "2" * 64,
            "updated_at": int(time.time()),
        },
    )
    with pytest.raises(AgentFailure) as raised:
        handle_run_operation(
            "status",
            _status_payload(agent_config, "b" * 64, run_id),
            agent_config,
            state,
        )
    assert raised.value.code == "RUN_STATE_INVALID"
