"""Approval-bound, asynchronous execution of one fixed Nextflow command."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from . import PROTOCOL_VERSION
from .commands import minimal_environment, run_to_logs
from .config import AgentConfig, verify_executable, verify_nextflow_jar
from .deployment import verify_deployment
from .errors import AgentFailure, ReturnCode
from .paths import PathGuard
from .preflight import recheck_container_artifacts, recheck_input_records
from .protocol import (
    require_bool,
    require_exact_fields,
    require_identifier,
    require_sha256,
    require_string,
)
from .state import StateStore

_TOKEN = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_KEYS = frozenset(
    {
        "dataset_manifest",
        "pipeline_spec",
        "execution_plan",
        "software_lock",
        "execution_profile",
        "validation_report",
        "test_report",
        "preflight_report",
    }
)
_TERMINAL_STATUSES = frozenset({"completed", "failed"})


@dataclass(frozen=True)
class RunRequest:
    run_id: str
    preflight_id: str
    preflight_token: str
    deployment_id: str
    profile_id: str
    profile_hash: str
    project_hash: str
    bundle_hash: str
    approval: dict[str, Any]
    resume_run_id: str | None


def handle_run_operation(
    operation: str,
    payload: dict[str, Any],
    config: AgentConfig,
    state: StateStore,
) -> dict[str, Any]:
    if operation == "status":
        return _status(payload, config, state)
    if operation == "abandon":
        return _abandon(payload, config, state)
    if operation in {"submit", "resume"}:
        return _submit(operation, payload, config, state)
    raise AgentFailure(
        ReturnCode.UNSUPPORTED_OPERATION,
        "UNSUPPORTED_OPERATION",
        "operation is not implemented by the fixed runner",
    )


def validate_resume_preflight(record: dict[str, Any], state: StateStore) -> None:
    """Bind a fresh resume preflight to the exact prior run paths and hashes."""

    resume_run_id = record.get("resume_run_id")
    if not isinstance(resume_run_id, str):
        return
    previous = state.read("runs", resume_run_id)
    expected = (
        ("profile_id", "profile_id"),
        ("profile_hash", "profile_hash"),
        ("project_hash", "project_hash"),
        ("deploy_dir", "deployment_dir"),
        ("work_dir", "work_dir"),
        ("output_dir", "output_dir"),
        ("cache_dir", "cache_dir"),
        ("directory_identities", "directory_identities"),
    )
    if previous.get("status") not in _TERMINAL_STATUSES or any(
        record.get(current) != previous.get(old) for current, old in expected
    ):
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "RESUME_PREFLIGHT_MISMATCH",
            "resume preflight does not match the exact prior run",
        )


def _submit(
    operation: str,
    payload: dict[str, Any],
    config: AgentConfig,
    state: StateStore,
) -> dict[str, Any]:
    request = _parse_run_request(operation, payload, config)
    preflight = state.read("preflights", request.preflight_id)
    deployment = state.read("deployments", request.deployment_id)
    previous = (
        state.read("runs", request.resume_run_id) if request.resume_run_id is not None else None
    )
    _validate_run_bindings(request, preflight, deployment, previous, config)
    now = int(time.time())
    run_directory = state.create_run_directory(request.run_id)
    state.create_supervisor_lease(request.run_id)
    lease_fd = state.acquire_supervisor_lease(request.run_id)
    try:
        client_isolation = state.create_run_isolation(request.run_id)
        overlay = run_directory / "network.config"
        argv, environment = _fixed_nextflow_invocation(
            preflight,
            config,
            run_directory,
            overlay,
            resume=previous is not None,
            client_isolation=client_isolation,
        )
        command_hash = _canonical_hash(list(argv))
        environment_hash = _canonical_hash(environment)
    except BaseException:
        os.close(lease_fd)
        raise
    record: dict[str, Any] = {
        "record_version": "1.0",
        "run_id": request.run_id,
        "status": "reserved",
        "return_code": None,
        "profile_id": request.profile_id,
        "profile_hash": request.profile_hash,
        "project_hash": request.project_hash,
        "bundle_hash": request.bundle_hash,
        "compatibility_hash": request.approval["compatibility_hash"],
        "authorization_id": request.approval["authorization_id"],
        "approval_actor": request.approval["actor"],
        "approved_at": request.approval["approved_at"],
        "artifact_hashes": request.approval["artifact_hashes"],
        "preflight_id": request.preflight_id,
        "deployment_id": request.deployment_id,
        "deployment_dir": preflight["deploy_dir"],
        "work_dir": preflight["work_dir"],
        "output_dir": preflight["output_dir"],
        "cache_dir": preflight["cache_dir"],
        "container_engine": preflight["container_engine"],
        "resume_run_id": request.resume_run_id,
        "directory_identities": (
            preflight.get("directory_identities") if previous is not None else None
        ),
        "run_directory": str(run_directory),
        "command_hash": command_hash,
        "environment_hash": environment_hash,
        "created_at": now,
        "updated_at": now,
    }
    reservation_created = False
    try:
        state.create("runs", request.run_id, record)
        reservation_created = True
        verify_deployment(deployment, config)
        recheck_input_records(preflight, config)
        recheck_container_artifacts(preflight, config)
        _recheck_storage(preflight, config, resume=previous is not None)
        state.claim("preflights", request.preflight_id, "consumed")
        consumed = {**preflight, "consumed": True, "consumed_by_run_id": request.run_id}
        state.replace("preflights", request.preflight_id, consumed)
        if previous is None:
            identities = _reserve_initial_paths(preflight, config)
            record = {**record, "directory_identities": identities}
            state.replace("runs", request.run_id, record)
        _write_network_overlay(
            run_directory,
            preflight["container_engine"],
            preflight["deploy_dir"],
            preflight["containers"],
        )
        submitted = {
            **record,
            "status": "submitted",
            "updated_at": int(time.time()),
        }
        state.replace("runs", request.run_id, submitted)
        _launch_supervisor(
            run_id=request.run_id,
            record=submitted,
            state=state,
            argv=argv,
            environment=environment,
            cwd=run_directory,
            run_directory=run_directory,
            timeout_seconds=config.limits.run_timeout_seconds,
            config=config,
            preflight=preflight,
            deployment=deployment,
            lease_fd=lease_fd,
        )
        os.close(lease_fd)
        lease_fd = -1
    except (AgentFailure, OSError, ValueError) as exc:
        if reservation_created:
            failed = {
                **record,
                "status": "failed",
                "return_code": int(ReturnCode.RUN_FAILED),
                "failure_code": (
                    exc.code if isinstance(exc, AgentFailure) else "RUN_LAUNCH_FAILED"
                ),
                "updated_at": int(time.time()),
            }
            state.replace("runs", request.run_id, failed)
        if isinstance(exc, AgentFailure):
            raise
        raise AgentFailure(
            ReturnCode.RUN_FAILED,
            "RUN_LAUNCH_FAILED",
            "the fixed Nextflow run could not be launched",
        ) from exc
    finally:
        if lease_fd >= 0:
            os.close(lease_fd)
    return {
        "run_id": request.run_id,
        "status": "submitted",
        "remote_work_dir": preflight["work_dir"],
        "result_dir": preflight["output_dir"],
        "command_hash": command_hash,
        "environment_hash": environment_hash,
    }


def _status(
    payload: dict[str, Any],
    config: AgentConfig,
    state: StateStore,
) -> dict[str, Any]:
    require_exact_fields(
        payload,
        required={"run_id", "profile_id", "profile_hash", "project_hash", "bundle_hash"},
    )
    run_id = require_identifier(payload["run_id"], "run_id")
    profile_id = require_identifier(payload["profile_id"], "profile_id")
    profile_hash = require_sha256(payload["profile_hash"], "profile_hash")
    project_hash = require_sha256(payload["project_hash"], "project_hash")
    bundle_hash = require_sha256(payload["bundle_hash"], "bundle_hash")
    try:
        record = state.read("runs", run_id)
    except AgentFailure as failure:
        if failure.code != "STATE_NOT_FOUND":
            raise
        raise _run_not_found() from failure
    if (
        profile_id != config.profile_id
        or profile_hash != config.profile_hash
        or record.get("profile_id") != profile_id
        or record.get("profile_hash") != profile_hash
        or record.get("project_hash") != project_hash
        or record.get("bundle_hash") != bundle_hash
        or record.get("status") == "abandoned"
    ):
        raise _run_not_found()
    record = _recover_abandoned_run(state, run_id, record)
    status = record.get("status")
    return_code = record.get("return_code")
    command_hash = record.get("command_hash")
    environment_hash = record.get("environment_hash")
    invalid_return_code = (
        (status in {"reserved", "submitted", "running"} and return_code is not None)
        or (status == "completed" and return_code != 0)
        or (
            status == "failed"
            and (
                isinstance(return_code, bool)
                or not isinstance(return_code, int)
                or not 1 <= return_code <= 255
            )
        )
    )
    if (
        status not in {"reserved", "submitted", "running", "completed", "failed"}
        or invalid_return_code
        or not isinstance(command_hash, str)
        or not isinstance(environment_hash, str)
        or _TOKEN.fullmatch(command_hash) is None
        or _TOKEN.fullmatch(environment_hash) is None
    ):
        raise AgentFailure(
            ReturnCode.INTERNAL_ERROR,
            "RUN_STATE_INVALID",
            "the run state record is internally inconsistent",
        )
    external_status = {
        "reserved": "submitted",
        "submitted": "submitted",
        "running": "running",
        "completed": "succeeded",
        "failed": "failed",
    }[status]
    return {
        "run_id": run_id,
        "status": external_status,
        "return_code": return_code,
        "command_hash": command_hash,
        "environment_hash": environment_hash,
    }


def _recover_abandoned_run(
    state: StateStore,
    run_id: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    status = record.get("status")
    if status not in {"reserved", "submitted", "running"}:
        return record
    updated_at = record.get("updated_at")
    if isinstance(updated_at, bool) or not isinstance(updated_at, int):
        raise AgentFailure(
            ReturnCode.INTERNAL_ERROR,
            "RUN_STATE_INVALID",
            "the run state record is internally inconsistent",
        )
    now = int(time.time())
    with state.try_supervisor_recovery_lease(run_id) as acquired:
        if not acquired:
            return record
        current = state.read("runs", run_id)
        current_status = current.get("status")
        if current_status not in {"reserved", "submitted", "running"}:
            return current
        failed = {
            **current,
            "status": "failed",
            "return_code": int(ReturnCode.RUN_FAILED),
            "failure_code": "SUPERVISOR_ABANDONED",
            "updated_at": now,
        }
        state.replace("runs", run_id, failed)
        return failed


def _abandon(
    payload: dict[str, Any],
    config: AgentConfig,
    state: StateStore,
) -> dict[str, Any]:
    required = {
        "run_id",
        "profile_id",
        "profile_hash",
        "project_hash",
        "bundle_hash",
        "deployment_id",
        "resume_run_id",
        "submitted_at",
        "approval",
    }
    require_exact_fields(payload, required=required)
    approval = payload.get("approval")
    if not isinstance(approval, dict):
        raise _schema("approval must be an object")
    require_exact_fields(approval, required={"key_id", "signature"})
    _verify_controller_attestation("abandon", payload, config)
    run_id = require_identifier(payload["run_id"], "run_id")
    profile_id = require_identifier(payload["profile_id"], "profile_id")
    profile_hash = require_sha256(payload["profile_hash"], "profile_hash")
    project_hash = require_sha256(payload["project_hash"], "project_hash")
    bundle_hash = require_sha256(payload["bundle_hash"], "bundle_hash")
    deployment_id = require_identifier(payload["deployment_id"], "deployment_id")
    resume_value = payload["resume_run_id"]
    resume_run_id = (
        None if resume_value is None else require_identifier(resume_value, "resume_run_id")
    )
    submitted_at = require_string(payload["submitted_at"], "submitted_at", maximum_bytes=64)
    _parse_utc_timestamp(submitted_at)
    if profile_id != config.profile_id or profile_hash != config.profile_hash:
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "PROFILE_BINDING_MISMATCH",
            "abandonment does not match this execution profile",
        )
    immutable = {
        "run_id": run_id,
        "profile_id": profile_id,
        "profile_hash": profile_hash,
        "project_hash": project_hash,
        "bundle_hash": bundle_hash,
        "deployment_id": deployment_id,
        "resume_run_id": resume_run_id,
        "submitted_at": submitted_at,
    }
    now = int(time.time())
    tombstone: dict[str, Any] = {
        "record_version": "1.0",
        **immutable,
        "status": "abandoned",
        "return_code": None,
        "command_hash": None,
        "environment_hash": None,
        "created_at": now,
        "updated_at": now,
    }
    try:
        state.create("runs", run_id, tombstone)
    except AgentFailure as failure:
        if failure.code != "STATE_ALREADY_EXISTS":
            raise
        current = state.read("runs", run_id)
        if current.get("status") != "abandoned" or any(
            current.get(key) != value for key, value in immutable.items()
        ):
            raise AgentFailure(
                ReturnCode.STATE_CONFLICT,
                "RUN_ALREADY_EXISTS",
                "the run identifier is already durably reserved",
            ) from failure
    return {"run_id": run_id, "status": "abandoned"}


def _parse_run_request(
    operation: str,
    payload: dict[str, Any],
    config: AgentConfig,
) -> RunRequest:
    common = {
        "run_id",
        "preflight_id",
        "preflight_token",
        "deployment_id",
        "profile_id",
        "profile_hash",
        "project_hash",
        "bundle_hash",
        "approval",
    }
    if operation == "submit":
        require_exact_fields(payload, required=common)
        resume_run_id = None
    else:
        require_exact_fields(payload, required=common | {"resume_run_id"})
        resume_run_id = require_identifier(payload["resume_run_id"], "resume_run_id")
    run_id = require_identifier(payload["run_id"], "run_id")
    if run_id == resume_run_id:
        raise _schema("run_id must identify a new resume attempt")
    profile_id = require_identifier(payload["profile_id"], "profile_id")
    profile_hash = require_sha256(payload["profile_hash"], "profile_hash")
    project_hash = require_sha256(payload["project_hash"], "project_hash")
    bundle_hash = require_sha256(payload["bundle_hash"], "bundle_hash")
    token = require_string(payload["preflight_token"], "preflight_token", maximum_bytes=256)
    if not _TOKEN.fullmatch(token):
        raise _schema("preflight_token is invalid")
    if profile_id != config.profile_id or profile_hash != config.profile_hash:
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "PROFILE_BINDING_MISMATCH",
            "run authorization does not match this execution profile",
        )
    _verify_controller_attestation(operation, payload, config)
    approval = _approval(payload["approval"], profile_hash, project_hash, bundle_hash)
    return RunRequest(
        run_id=run_id,
        preflight_id=require_identifier(payload["preflight_id"], "preflight_id"),
        preflight_token=token,
        deployment_id=require_identifier(payload["deployment_id"], "deployment_id"),
        profile_id=profile_id,
        profile_hash=profile_hash,
        project_hash=project_hash,
        bundle_hash=bundle_hash,
        approval=approval,
        resume_run_id=resume_run_id,
    )


def _approval(
    value: Any,
    profile_hash: str,
    project_hash: str,
    bundle_hash: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _schema("approval must be an object")
    require_exact_fields(
        value,
        required={
            "approved",
            "authorization_id",
            "actor",
            "approved_at",
            "artifact_hashes",
            "bundle_hash",
            "compatibility_hash",
            "key_id",
            "signature",
        },
    )
    if require_bool(value["approved"], "approval.approved") is not True:
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "APPROVAL_REQUIRED",
            "explicit real-data approval is required",
        )
    authorization_id = require_identifier(value["authorization_id"], "approval.authorization_id")
    if not authorization_id.startswith("auth-"):
        raise _schema("approval.authorization_id is invalid")
    actor = require_string(value["actor"], "approval.actor", maximum_bytes=256)
    approved_at = require_string(value["approved_at"], "approval.approved_at", maximum_bytes=64)
    _parse_utc_timestamp(approved_at)
    hashes = value["artifact_hashes"]
    if not isinstance(hashes, dict):
        raise _schema("approval.artifact_hashes must be an object")
    require_exact_fields(hashes, required=set(_ARTIFACT_KEYS))
    artifact_hashes = {
        key: require_sha256(item, f"approval.artifact_hashes.{key}") for key, item in hashes.items()
    }
    approval_bundle = require_sha256(value["bundle_hash"], "approval.bundle_hash")
    compatibility = require_sha256(value["compatibility_hash"], "approval.compatibility_hash")
    require_identifier(value["key_id"], "approval.key_id")
    require_sha256(value["signature"], "approval.signature")
    if (
        approval_bundle != bundle_hash
        or artifact_hashes["execution_profile"] != profile_hash
        or _project_hash(artifact_hashes) != project_hash
        or _compatibility_hash(profile_hash, project_hash, bundle_hash) != compatibility
    ):
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "APPROVAL_ARTIFACT_MISMATCH",
            "approval does not bind the exact execution artifacts",
        )
    return {
        "approved": True,
        "authorization_id": authorization_id,
        "actor": actor,
        "approved_at": approved_at,
        "artifact_hashes": artifact_hashes,
        "bundle_hash": approval_bundle,
        "compatibility_hash": compatibility,
    }


def _verify_controller_attestation(
    operation: str,
    payload: dict[str, Any],
    config: AgentConfig,
) -> None:
    approval = payload.get("approval")
    if not isinstance(approval, dict):
        raise _schema("approval must be an object")
    key_id = approval.get("key_id")
    signature = approval.get("signature")
    if (
        not isinstance(key_id, str)
        or not isinstance(signature, str)
        or key_id != config.approval_key_id
        or not re.fullmatch(r"[0-9a-f]{64}", signature)
    ):
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "APPROVAL_ATTESTATION_INVALID",
            "controller approval attestation is invalid",
        )
    unsigned_approval = {key: value for key, value in approval.items() if key != "signature"}
    signed_payload = {**payload, "approval": unsigned_approval}
    material = json.dumps(
        {
            "protocol_version": PROTOCOL_VERSION,
            "operation": operation,
            "payload": signed_payload,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    expected = hmac.new(config.approval_hmac_key, material, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "APPROVAL_ATTESTATION_INVALID",
            "controller approval attestation is invalid",
        )


def _validate_run_bindings(
    request: RunRequest,
    preflight: dict[str, Any],
    deployment: dict[str, Any],
    previous: dict[str, Any] | None,
    config: AgentConfig,
) -> None:
    token_hash = preflight.get("token_hash")
    if not isinstance(token_hash, str) or not hmac.compare_digest(
        token_hash,
        hashlib.sha256(request.preflight_token.encode("ascii")).hexdigest(),
    ):
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "PREFLIGHT_TOKEN_INVALID",
            "the preflight capability token is invalid",
        )
    now = int(time.time())
    issued_at = preflight.get("issued_at")
    expires_at = preflight.get("expires_at")
    if (
        preflight.get("status") != "passed"
        or preflight.get("consumed") is not False
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or now > expires_at
    ):
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "PREFLIGHT_STALE_OR_CONSUMED",
            "a fresh unconsumed preflight is required",
        )
    core = request.approval["artifact_hashes"]
    core_preflight = {
        key: core[key]
        for key in core
        if key in _ARTIFACT_KEYS - {"validation_report", "test_report", "preflight_report"}
    }
    if (
        preflight.get("profile_id") != request.profile_id
        or preflight.get("profile_hash") != request.profile_hash
        or preflight.get("project_hash") != request.project_hash
        or preflight.get("artifact_hashes") != core_preflight
        or preflight.get("network_disabled") is not True
    ):
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "PREFLIGHT_BINDING_MISMATCH",
            "preflight does not bind the exact approved artifacts",
        )
    approved_time = int(_parse_utc_timestamp(request.approval["approved_at"]).timestamp())
    if approved_time < issued_at - 300 or approved_time > now + 300:
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "APPROVAL_TIME_INVALID",
            "approval time is outside the accepted preflight window",
        )
    if (
        deployment.get("status") != "complete"
        or deployment.get("profile_id") != request.profile_id
        or deployment.get("profile_hash") != request.profile_hash
        or deployment.get("project_hash") != request.project_hash
        or deployment.get("bundle_hash") != request.bundle_hash
        or deployment.get("deployment_dir") != preflight.get("deploy_dir")
    ):
        raise AgentFailure(
            ReturnCode.DEPLOYMENT_FAILED,
            "DEPLOYMENT_BINDING_MISMATCH",
            "deployment does not bind the exact approved artifacts",
        )
    if previous is None:
        if (
            request.resume_run_id is not None
            or preflight.get("resume_run_id") is not None
            or deployment.get("preflight_id") != request.preflight_id
        ):
            raise AgentFailure(
                ReturnCode.APPROVAL_REQUIRED,
                "SUBMISSION_MODE_MISMATCH",
                "initial submission does not match its preflight",
            )
        return
    if (
        request.resume_run_id is None
        or previous.get("run_id") != request.resume_run_id
        or previous.get("status") not in _TERMINAL_STATUSES
        or preflight.get("resume_run_id") != request.resume_run_id
        or previous.get("profile_id") != request.profile_id
        or previous.get("profile_hash") != request.profile_hash
        or previous.get("project_hash") != request.project_hash
        or previous.get("bundle_hash") != request.bundle_hash
        or previous.get("compatibility_hash") != request.approval["compatibility_hash"]
        or previous.get("deployment_id") != request.deployment_id
        or previous.get("deployment_dir") != preflight.get("deploy_dir")
        or previous.get("work_dir") != preflight.get("work_dir")
        or previous.get("output_dir") != preflight.get("output_dir")
        or previous.get("cache_dir") != preflight.get("cache_dir")
        or previous.get("directory_identities") != preflight.get("directory_identities")
    ):
        raise AgentFailure(
            ReturnCode.APPROVAL_REQUIRED,
            "RESUME_INCOMPATIBLE",
            "resume is not compatible with the exact prior run",
        )
    del config


def _recheck_storage(
    preflight: dict[str, Any],
    config: AgentConfig,
    *,
    resume: bool,
) -> None:
    guard = PathGuard()
    minimum = preflight.get("minimum_free_bytes")
    if isinstance(minimum, bool) or not isinstance(minimum, int):
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "PREFLIGHT_RECORD_INVALID",
            "preflight storage evidence is invalid",
        )
    checks = (
        ("work", preflight.get("work_dir"), config.work_roots, not resume),
        ("output", preflight.get("output_dir"), config.output_roots, not resume),
        ("cache", preflight.get("cache_dir"), config.cache_roots, False),
    )
    identities = preflight.get("directory_identities")
    if resume and (not isinstance(identities, dict) or set(identities) != {"work", "output"}):
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "PREFLIGHT_RECORD_INVALID",
            "resume directory identity evidence is invalid",
        )
    resume_identities = identities if isinstance(identities, dict) else {}
    for label, path, roots, must_be_absent in checks:
        if not isinstance(path, str):
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "PREFLIGHT_RECORD_INVALID",
                "preflight storage evidence is invalid",
            )
        _authorized, free, observed_identity = guard.test_writable_parent(
            path,
            roots,
            target_must_be_absent=must_be_absent,
            target_private=resume and label in {"work", "output"},
        )
        if resume and label in {"work", "output"} and observed_identity != resume_identities[label]:
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "RESUME_DIRECTORY_CHANGED",
                "resume directories changed after their original reservation",
            )
        if free < minimum:
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "INSUFFICIENT_SPACE",
                "free space fell below the preflight threshold",
            )


def _reserve_initial_paths(
    preflight: dict[str, Any],
    config: AgentConfig,
) -> dict[str, dict[str, int]]:
    guard = PathGuard()
    _output, output_identity = guard.create_directory_exclusive(
        preflight["output_dir"], config.output_roots
    )
    _work, work_identity = guard.create_directory_exclusive(
        preflight["work_dir"], config.work_roots
    )
    return {"work": work_identity, "output": output_identity}


def _recheck_run_directories(record: dict[str, Any], config: AgentConfig) -> None:
    identities = record.get("directory_identities")
    if not isinstance(identities, dict) or set(identities) != {"work", "output"}:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "RUN_DIRECTORY_IDENTITY_INVALID",
            "run directory identity evidence is invalid",
        )
    guard = PathGuard()
    for label, path_key, roots in (
        ("work", "work_dir", config.work_roots),
        ("output", "output_dir", config.output_roots),
    ):
        path = record.get(path_key)
        expected = identities.get(label)
        if (
            not isinstance(path, str)
            or not isinstance(expected, dict)
            or set(expected)
            != {
                "device",
                "inode",
                "owner",
                "mode",
            }
        ):
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "RUN_DIRECTORY_IDENTITY_INVALID",
                "run directory identity evidence is invalid",
            )
        _authorized, _free, observed = guard.test_writable_parent(
            path,
            roots,
            target_must_be_absent=False,
            target_private=True,
        )
        if observed != expected:
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "RUN_DIRECTORY_CHANGED",
                "a reserved run directory changed before execution",
            )


def _verify_run_executables(config: AgentConfig, engine: str) -> None:
    if engine == "apptainer":
        runtime = config.executables.apptainer
        runtime_identity = config.executables.apptainer_identity
    elif engine == "docker":
        runtime = config.executables.docker
        runtime_identity = config.executables.docker_identity
    else:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "CONTAINER_RUNTIME_UNAVAILABLE",
            "the selected container runtime is unavailable",
        )
    if runtime is None:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "CONTAINER_RUNTIME_UNAVAILABLE",
            "the selected container runtime is unavailable",
        )
    verify_executable(runtime, runtime_identity)
    verify_executable(config.executables.java, config.executables.java_identity)
    verify_executable(config.executables.nextflow, config.executables.nextflow_identity)
    verify_nextflow_jar(config)


def _write_network_overlay(
    run_directory: Path,
    engine: str,
    deployment: str,
    containers: Any,
) -> Path:
    include = f"includeConfig {_groovy_quote(deployment + '/nextflow.config')}\n"
    if engine == "docker":
        content = include + (
            "process.executor = 'local'\n"
            "wave.enabled = false\n"
            "tower.enabled = false\n"
            "fusion.enabled = false\n"
            "docker.enabled = true\n"
            "apptainer.enabled = false\n"
            "singularity.enabled = false\n"
            "docker.runOptions = '--network none --pull=never'\n"
        )
    elif engine == "apptainer":
        selectors = _apptainer_container_selectors(containers)
        content = (
            include
            + (
                "process.executor = 'local'\n"
                "wave.enabled = false\n"
                "tower.enabled = false\n"
                "fusion.enabled = false\n"
                "docker.enabled = false\n"
                "apptainer.enabled = true\n"
                "singularity.enabled = false\n"
                "apptainer.runOptions = "
                "'--containall --no-home --cleanenv --net --network none'\n"
                "singularity.runOptions = "
                "'--containall --no-home --cleanenv --net --network none'\n"
            )
            + selectors
        )
    else:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "CONTAINER_RUNTIME_UNAVAILABLE",
            "the preflight container runtime is unsupported",
        )
    path = run_directory / "network.config"
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o400)
    try:
        payload = content.encode("utf-8")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise OSError("network overlay write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _apptainer_container_selectors(containers: Any) -> str:
    if not isinstance(containers, list):
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "CONTAINER_RECORD_INVALID",
            "the preflight container evidence is invalid",
        )
    paths: dict[str, str] = {}
    for container in containers:
        if not isinstance(container, dict):
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "CONTAINER_RECORD_INVALID",
                "the preflight container evidence is invalid",
            )
        name = container.get("name")
        local_path = container.get("local_path")
        if name not in {"fastqc", "fastp", "multiqc"} or not isinstance(local_path, str):
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "CONTAINER_RECORD_INVALID",
                "the preflight container evidence is invalid",
            )
        paths[name] = local_path
    if not {"fastqc", "multiqc"} <= paths.keys():
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "CONTAINER_RECORD_INVALID",
            "the preflight container evidence is incomplete",
        )
    labels = {
        "fastqc_raw": paths["fastqc"],
        "fastqc_post_trim": paths["fastqc"],
        "multiqc": paths["multiqc"],
    }
    if "fastp" in paths:
        labels["fastp"] = paths["fastp"]
    lines = ["process {"]
    for label, local_path in sorted(labels.items()):
        lines.append(f"    withLabel: {_groovy_quote(label)} {{")
        lines.append(f"        container = {_groovy_quote(local_path)}")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _fixed_nextflow_invocation(
    preflight: dict[str, Any],
    config: AgentConfig,
    run_directory: Path,
    overlay: Path,
    *,
    resume: bool,
    client_isolation: dict[str, Path],
) -> tuple[tuple[str, ...], dict[str, str]]:
    deployment = str(preflight["deploy_dir"])
    arguments = [
        str(config.executables.nextflow),
        "-C",
        str(overlay),
        "-log",
        str(run_directory / "nextflow.log"),
        "run",
        deployment,
        "-profile",
        "local",
        "-work-dir",
        str(preflight["work_dir"]),
        "--output_dir",
        str(preflight["output_dir"]),
        "--samplesheet",
        str(PurePosixPath(deployment) / "assets" / "samplesheet.csv"),
    ]
    if resume:
        arguments.append("-resume")
    extra = _run_client_environment(config, client_isolation)
    runtime = (
        config.executables.apptainer
        if preflight["container_engine"] == "apptainer"
        else config.executables.docker
    )
    if runtime is None:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "CONTAINER_RUNTIME_UNAVAILABLE",
            "the selected container runtime is unavailable",
        )
    if preflight["container_engine"] == "apptainer":
        extra["APPTAINER_CACHEDIR"] = str(preflight["cache_dir"])
        extra["SINGULARITY_CACHEDIR"] = str(preflight["cache_dir"])
    environment = minimal_environment(
        executable_paths=(runtime, config.executables.java, config.executables.nextflow),
        extra=extra,
    )
    return tuple(arguments), environment


def _run_client_environment(
    config: AgentConfig,
    isolation: dict[str, Path],
) -> dict[str, str]:
    if set(isolation) != {
        "client-home",
        "docker-config",
        "apptainer-config",
        "nxf-home",
        "tmp",
    }:
        raise AgentFailure(
            ReturnCode.INTERNAL_ERROR,
            "CLIENT_ISOLATION_INVALID",
            "private client isolation directories are unavailable",
        )
    return {
        "HOME": str(isolation["client-home"]),
        "JAVA_CMD": str(config.executables.java),
        "NXF_HOME": str(isolation["nxf-home"]),
        "NXF_BIN": str(config.nextflow_jar),
        "NXF_VER": config.nextflow_version,
        "NXF_TEMP": str(isolation["tmp"]),
        "TMPDIR": str(isolation["tmp"]),
        "DOCKER_CONFIG": str(isolation["docker-config"]),
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "APPTAINER_CONFIGDIR": str(isolation["apptainer-config"]),
        "SINGULARITY_CONFIGDIR": str(isolation["apptainer-config"]),
    }


def _groovy_quote(value: str) -> str:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AgentFailure(
            ReturnCode.PROTOCOL_ERROR,
            "UNSAFE_PATH",
            "deployment path cannot be represented in the fixed config overlay",
        )
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _launch_supervisor(
    *,
    run_id: str,
    record: dict[str, Any],
    state: StateStore,
    argv: tuple[str, ...],
    environment: dict[str, str],
    cwd: Path,
    run_directory: Path,
    timeout_seconds: float,
    config: AgentConfig,
    preflight: dict[str, Any],
    deployment: dict[str, Any],
    lease_fd: int,
) -> None:
    if os.name != "posix" or not hasattr(os, "fork"):
        raise AgentFailure(
            ReturnCode.RUN_FAILED,
            "PLATFORM_UNSUPPORTED",
            "background execution requires the supported POSIX deployment platform",
        )
    read_fd, write_fd = os.pipe()
    first = os.fork()
    if first == 0:
        os.close(read_fd)
        try:
            os.setsid()
            supervisor = os.fork()
            if supervisor > 0:
                os.write(write_fd, str(supervisor).encode("ascii"))
                os.close(write_fd)
                os.close(lease_fd)
                os._exit(0)
            os.close(write_fd)
            _detach_standard_streams()
            os.chdir("/")
            os.umask(0o077)
            _execute_run(
                run_id=run_id,
                record=record,
                state=state,
                argv=argv,
                environment=environment,
                cwd=cwd,
                run_directory=run_directory,
                timeout_seconds=timeout_seconds,
                config=config,
                preflight=preflight,
                deployment=deployment,
                lease_fd=lease_fd,
            )
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        marker = os.read(read_fd, 64)
    finally:
        os.close(read_fd)
    _waited, status = os.waitpid(first, 0)
    if not marker or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise AgentFailure(
            ReturnCode.RUN_FAILED,
            "RUN_LAUNCH_FAILED",
            "the fixed background supervisor could not be started",
        )


def _execute_run(
    *,
    run_id: str,
    record: dict[str, Any],
    state: StateStore,
    argv: tuple[str, ...],
    environment: dict[str, str],
    cwd: Path,
    run_directory: Path,
    timeout_seconds: float,
    config: AgentConfig,
    preflight: dict[str, Any],
    deployment: dict[str, Any],
    lease_fd: int,
) -> None:
    try:
        current = state.read("runs", run_id)
        if (
            current.get("status") != "submitted"
            or current.get("command_hash") != record.get("command_hash")
            or current.get("environment_hash") != record.get("environment_hash")
        ):
            return
        running = {
            **record,
            "status": "running",
            "supervisor_pid": os.getpid(),
            "updated_at": int(time.time()),
        }
        try:
            # This second descriptor-anchored pass happens while the supervisor
            # lease is held, immediately before Popen.
            verify_deployment(deployment, config)
            recheck_input_records(preflight, config)
            recheck_container_artifacts(preflight, config)
            _recheck_run_directories(record, config)
            _verify_run_executables(config, str(preflight["container_engine"]))
            state.replace("runs", run_id, running)
            result = run_to_logs(
                argv,
                cwd=cwd,
                env=environment,
                timeout_seconds=timeout_seconds,
                stdout_path=run_directory / "stdout.log",
                stderr_path=run_directory / "stderr.log",
                job_lease_fd=lease_fd,
            )
            return_code = (
                int(ReturnCode.TIMEOUT)
                if result.timed_out
                else _normalize_process_return_code(result.return_code)
            )
            final = {
                **running,
                "status": "completed" if return_code == 0 else "failed",
                "return_code": return_code,
                "updated_at": int(time.time()),
            }
            state.replace("runs", run_id, final)
        except BaseException:
            with suppress(BaseException):
                state.replace(
                    "runs",
                    run_id,
                    {
                        **running,
                        "status": "failed",
                        "return_code": int(ReturnCode.RUN_FAILED),
                        "updated_at": int(time.time()),
                    },
                )
    finally:
        os.close(lease_fd)


def _detach_standard_streams() -> None:
    descriptor = os.open(os.devnull, os.O_RDWR)
    try:
        for target in (0, 1, 2):
            os.dup2(descriptor, target)
    finally:
        if descriptor > 2:
            os.close(descriptor)


def _normalize_process_return_code(value: int) -> int:
    if value == 0 or 1 <= value <= 255:
        return value
    if -127 <= value < 0:
        return 128 + abs(value)
    return int(ReturnCode.RUN_FAILED)


def _parse_utc_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _schema("approval.approved_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _schema("approval.approved_at must include a timezone")
    return parsed.astimezone(timezone.utc)  # noqa: UP017


def _project_hash(hashes: dict[str, str]) -> str:
    return _canonical_hash(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        }
    )


def _compatibility_hash(profile_hash: str, project_hash: str, bundle_hash: str) -> str:
    return _canonical_hash(
        {
            "bundle_hash": bundle_hash,
            "execution_profile": profile_hash,
            "project_hash": project_hash,
        }
    )


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _schema(message: str) -> AgentFailure:
    return AgentFailure(ReturnCode.PROTOCOL_ERROR, "SCHEMA_ERROR", message)


def _run_not_found() -> AgentFailure:
    return AgentFailure(
        ReturnCode.PATH_UNAVAILABLE,
        "RUN_NOT_FOUND",
        "no run matched the supplied immutable bindings",
    )


__all__ = ["handle_run_operation", "validate_resume_preflight"]
