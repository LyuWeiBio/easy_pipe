"""Dormant, pure protocol-v2 contracts for future scheduler execution.

This module is deliberately not imported by the v1 service, configuration
loader, dispatcher, runner, or client.  It performs only bounded validation,
canonical serialization, and immutable evidence construction.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, cast

from .slurm import (
    SlurmContractError,
    SlurmJobRef,
    SlurmObservation,
    map_slurm_observation,
)

PROTOCOL_VERSION = "2.0"

SchedulerOperation = Literal["health", "preflight", "deploy", "submit", "status", "resume"]
MappedState = Literal["queued", "active", "succeeded", "failed", "indeterminate"]
EvidenceSource = Literal["squeue", "sacct", "reconciled"]

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_JOB_ID = re.compile(r"[1-9][0-9]{0,9}", re.ASCII)
_SUBMIT_TIME = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]",
    re.ASCII,
)
_RAW_STATE = re.compile(
    r"(?:[A-Z][A-Z_]{0,63}|CANCELLED by (?:0|[1-9][0-9]{0,9}))",
    re.ASCII,
)
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,63}", re.ASCII)
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)

_ENVELOPE_FIELDS = frozenset({"protocol_version", "request_id", "operation", "payload"})
_OPERATIONS = frozenset({"health", "preflight", "deploy", "submit", "status", "resume"})
_PROFILE_BINDINGS = frozenset(
    {"profile_version", "profile_id", "profile_hash", "scheduler_policy_hash"}
)
_PREFLIGHT_FIELDS = _PROFILE_BINDINGS | {
    "preflight_id",
    "project_hash",
    "artifact_hashes",
    "source_host",
    "execution_host",
    "host_relation",
    "source_paths",
    "execution_paths",
    "path_mapping",
    "deploy_dir",
    "work_dir",
    "output_dir",
    "cache_dir",
    "container_engine",
    "containers",
    "minimum_free_bytes",
    "network_disabled",
    "resume_run_id",
}
_DEPLOY_FIELDS = _PROFILE_BINDINGS | {
    "deployment_id",
    "preflight_id",
    "project_hash",
    "bundle_hash",
    "deployment_dir",
    "files",
}
_SUBMIT_FIELDS = _PROFILE_BINDINGS | {
    "run_id",
    "preflight_id",
    "preflight_token",
    "deployment_id",
    "project_hash",
    "bundle_hash",
    "approval",
}
_STATUS_FIELDS = _PROFILE_BINDINGS | {
    "run_id",
    "project_hash",
    "bundle_hash",
}
_RESUME_FIELDS = _SUBMIT_FIELDS | {"resume_run_id"}
_FIELDS_BY_OPERATION: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "health": frozenset(),
        "preflight": frozenset(_PREFLIGHT_FIELDS),
        "deploy": frozenset(_DEPLOY_FIELDS),
        "submit": frozenset(_SUBMIT_FIELDS),
        "status": frozenset(_STATUS_FIELDS),
        "resume": frozenset(_RESUME_FIELDS),
    }
)

_PREFLIGHT_ARTIFACT_HASHES = frozenset(
    {
        "dataset_manifest",
        "pipeline_spec",
        "execution_plan",
        "software_lock",
        "execution_profile",
    }
)
_APPROVAL_ARTIFACT_HASHES = _PREFLIGHT_ARTIFACT_HASHES | {
    "validation_report",
    "test_report",
    "preflight_report",
}
_APPROVAL_FIELDS = frozenset(
    {
        "approved",
        "authorization_id",
        "actor",
        "approved_at",
        "artifact_hashes",
        "bundle_hash",
        "compatibility_hash",
        "key_id",
        "signature",
    }
)
_CONTAINER_FIELDS = frozenset({"name", "image", "digest", "local_path", "file_sha256"})
_MAPPING_FIELDS = frozenset({"source_prefix", "execution_prefix"})
_FILE_FIELDS = frozenset({"path", "size", "sha256", "content_base64"})
_EVIDENCE_FIELDS = frozenset(
    {
        "job_id",
        "submission_marker",
        "submitted_at",
        "batch_script_sha256",
        "scheduler_policy_hash",
        "raw_state",
        "mapped_state",
        "reason_code",
        "exit_code",
        "signal",
        "source",
    }
)
_RECONCILED_REASON_CODES = frozenset(
    {
        "SLURM_OBSERVATION_CONFLICT",
        "SLURM_OBSERVATION_MISSING",
        "SLURM_TERMINAL_STATE_REGRESSION",
    }
)

_MAX_PATH_BYTES = 4096
_MAX_TEXT_BYTES = 4096
_MAX_ARRAY_ITEMS = 100_000
_MAX_DEPLOYMENT_FILES = 1024
_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_JOB_ID = 4_294_967_295
_MAX_REQUEST_BYTES = 64 * 1024 * 1024
_MAX_JSON_NESTING = 128


class SchedulerProtocolError(ValueError):
    """A protocol-v2 value violates the dormant scheduler contract."""


@dataclass(frozen=True)
class SchedulerRequest:
    """One validated and recursively immutable protocol-v2 request."""

    protocol_version: Literal["2.0"]
    request_id: str
    operation: SchedulerOperation
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class SlurmRunEvidence:
    """Strict durable evidence for one marker- and attempt-bound Slurm job."""

    job_id: str
    submission_marker: str
    submitted_at: str
    batch_script_sha256: str
    scheduler_policy_hash: str
    raw_state: str | None
    mapped_state: MappedState
    reason_code: str
    exit_code: int | None
    signal: int | None
    source: EvidenceSource


def decode_json_line(data: Any) -> Any:
    """Decode one bounded duplicate-free UTF-8 JSON value without reading I/O."""

    if not isinstance(data, bytes) or not 0 < len(data) <= _MAX_REQUEST_BYTES:
        raise SchedulerProtocolError("request JSON must be bounded bytes")
    try:
        text = data.decode("utf-8")
        _reject_excessive_nesting(text)
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise SchedulerProtocolError("request JSON must be strict duplicate-free UTF-8") from exc


def parse_request(value: Any) -> SchedulerRequest:
    """Parse one exact scheduler protocol-v2 envelope without dispatching it."""

    envelope = _object(value, "request")
    _exact_fields(envelope, _ENVELOPE_FIELDS, "request")
    if envelope["protocol_version"] != PROTOCOL_VERSION:
        raise SchedulerProtocolError("protocol_version must be exactly 2.0")
    request_id = _identifier(envelope["request_id"], "request_id")
    operation_value = envelope["operation"]
    if not isinstance(operation_value, str) or operation_value not in _OPERATIONS:
        raise SchedulerProtocolError("operation is not supported by scheduler protocol v2")
    operation = cast(SchedulerOperation, operation_value)
    payload = _object(envelope["payload"], "payload")
    _exact_fields(payload, _FIELDS_BY_OPERATION[operation], f"{operation} payload")
    _validate_payload(operation, payload)
    return SchedulerRequest(
        protocol_version="2.0",
        request_id=request_id,
        operation=operation,
        payload=cast(Mapping[str, Any], _freeze_json(payload)),
    )


def canonical_hmac_envelope_bytes(request: SchedulerRequest) -> bytes:
    """Return canonical submit/resume attestation bytes with literal version 2.0.

    As in protocol v1, ``request_id`` is transport metadata and is not signed.
    The signature value itself is removed while every other approval and
    scheduler binding remains covered.
    """

    if not isinstance(request, SchedulerRequest):
        raise SchedulerProtocolError("request must be a validated SchedulerRequest")
    validated = parse_request(
        {
            "protocol_version": request.protocol_version,
            "request_id": request.request_id,
            "operation": request.operation,
            "payload": _thaw_json(request.payload),
        }
    )
    if validated.operation not in {"submit", "resume"}:
        raise SchedulerProtocolError("only submit and resume have HMAC envelope bytes")
    payload = cast(dict[str, Any], _thaw_json(validated.payload))
    approval = cast(dict[str, Any], payload["approval"])
    payload["approval"] = {key: item for key, item in approval.items() if key != "signature"}
    envelope = {
        "protocol_version": "2.0",
        "operation": validated.operation,
        "payload": payload,
    }
    return json.dumps(
        envelope,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def parse_slurm_run_evidence(value: Any) -> SlurmRunEvidence:
    """Parse one exact Slurm evidence record, including indeterminate results."""

    record = _object(value, "Slurm run evidence")
    _exact_fields(record, _EVIDENCE_FIELDS, "Slurm run evidence")
    job_id = _job_id(record["job_id"])
    marker = _digest(record["submission_marker"], "submission_marker")
    submitted_at = _submit_time(record["submitted_at"])
    script_hash = _digest(record["batch_script_sha256"], "batch_script_sha256")
    policy_hash = _digest(record["scheduler_policy_hash"], "scheduler_policy_hash")

    raw_value = record["raw_state"]
    if raw_value is None:
        raw_state = None
    elif isinstance(raw_value, str) and _RAW_STATE.fullmatch(raw_value):
        raw_state = raw_value
        cancelled = re.fullmatch(r"CANCELLED by ([0-9]+)", raw_state, re.ASCII)
        if cancelled is not None and int(cancelled.group(1)) > _MAX_JOB_ID:
            raise SchedulerProtocolError("raw_state cancellation UID is out of range")
    else:
        raise SchedulerProtocolError("raw_state is malformed, truncated, or unsafe")

    mapped_value = record["mapped_state"]
    if mapped_value not in {"queued", "active", "succeeded", "failed", "indeterminate"}:
        raise SchedulerProtocolError("mapped_state is not supported")
    mapped_state = cast(MappedState, mapped_value)
    reason_code = record["reason_code"]
    if not isinstance(reason_code, str) or not _REASON.fullmatch(reason_code):
        raise SchedulerProtocolError("reason_code must be one stable uppercase code")
    exit_code = _optional_byte(record["exit_code"], "exit_code")
    signal = _optional_byte(record["signal"], "signal")
    if (exit_code is None) != (signal is None):
        raise SchedulerProtocolError("exit_code and signal must be present or absent together")

    source_value = record["source"]
    if source_value not in {"squeue", "sacct", "reconciled"}:
        raise SchedulerProtocolError("source is not supported")
    source = cast(EvidenceSource, source_value)
    expected_state, expected_reason = _derive_scheduler_mapping(
        job_id=job_id,
        submission_marker=marker,
        submitted_at=submitted_at,
        raw_state=raw_state,
        exit_code=exit_code,
        signal=signal,
        source=source,
        reason_code=reason_code,
    )
    if mapped_state != expected_state or reason_code != expected_reason:
        raise SchedulerProtocolError(
            "mapped_state and reason_code must match the derived scheduler evidence"
        )

    return SlurmRunEvidence(
        job_id=job_id,
        submission_marker=marker,
        submitted_at=submitted_at,
        batch_script_sha256=script_hash,
        scheduler_policy_hash=policy_hash,
        raw_state=raw_state,
        mapped_state=mapped_state,
        reason_code=reason_code,
        exit_code=exit_code,
        signal=signal,
        source=source,
    )


def _derive_scheduler_mapping(
    *,
    job_id: str,
    submission_marker: str,
    submitted_at: str,
    raw_state: str | None,
    exit_code: int | None,
    signal: int | None,
    source: EvidenceSource,
    reason_code: str,
) -> tuple[MappedState, str]:
    if source == "reconciled":
        if (
            raw_state is not None
            or exit_code is not None
            or signal is not None
            or reason_code not in _RECONCILED_REASON_CODES
        ):
            raise SchedulerProtocolError(
                "reconciled evidence must be one approved indeterminate summary"
            )
        return "indeterminate", reason_code
    if raw_state is None:
        raise SchedulerProtocolError("direct scheduler evidence requires raw_state")
    if source == "squeue" and exit_code is not None:
        raise SchedulerProtocolError("squeue evidence cannot contain exit evidence")

    cancelled = re.fullmatch(r"CANCELLED by ([0-9]+)", raw_state, re.ASCII)
    state = "CANCELLED" if cancelled is not None else raw_state
    cancelled_by_uid = None if cancelled is None else int(cancelled.group(1))
    if source == "squeue" and cancelled_by_uid is not None:
        raise SchedulerProtocolError("squeue evidence cannot carry a cancellation UID")
    try:
        observation = SlurmObservation(
            source=source,
            job=SlurmJobRef(
                job_id=job_id,
                submission_marker=submission_marker,
                submitted_at=submitted_at,
            ),
            state=state,
            exit_code=None if exit_code is None else (exit_code, cast(int, signal)),
            cancelled_by_uid=cancelled_by_uid,
        )
        mapped = map_slurm_observation(observation)
    except SlurmContractError as exc:
        raise SchedulerProtocolError("scheduler evidence violates the Slurm contract") from exc
    return mapped.state, mapped.code


def _validate_payload(operation: SchedulerOperation, payload: dict[str, Any]) -> None:
    if operation == "health":
        return
    _profile_bindings(payload)
    if operation == "preflight":
        _validate_preflight(payload)
    elif operation == "deploy":
        _validate_deploy(payload)
    elif operation in {"submit", "resume"}:
        _validate_run_mutation(operation, payload)
    else:
        _validate_status(payload)


def _profile_bindings(payload: dict[str, Any]) -> None:
    if payload["profile_version"] != "2.0":
        raise SchedulerProtocolError("profile_version must be exactly 2.0")
    _identifier(payload["profile_id"], "profile_id")
    _digest(payload["profile_hash"], "profile_hash")
    _digest(payload["scheduler_policy_hash"], "scheduler_policy_hash")


def _validate_preflight(payload: dict[str, Any]) -> None:
    _identifier(payload["preflight_id"], "preflight_id")
    _digest(payload["project_hash"], "project_hash")
    hashes = _object(payload["artifact_hashes"], "artifact_hashes")
    _exact_fields(hashes, _PREFLIGHT_ARTIFACT_HASHES, "artifact_hashes")
    for name, value in hashes.items():
        _digest(value, f"artifact_hashes.{name}")
    if hashes["execution_profile"] != payload["profile_hash"]:
        raise SchedulerProtocolError("artifact_hashes do not bind profile_hash")
    project_hash = _canonical_hash(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        }
    )
    if project_hash != payload["project_hash"]:
        raise SchedulerProtocolError("artifact_hashes do not bind project_hash")
    _identifier(payload["source_host"], "source_host")
    _identifier(payload["execution_host"], "execution_host")
    if payload["host_relation"] not in {"same", "shared"}:
        raise SchedulerProtocolError("host_relation must be same or shared")
    _path_array(payload["source_paths"], "source_paths")
    _path_array(payload["execution_paths"], "execution_paths")
    mappings = _array(payload["path_mapping"], "path_mapping", maximum=128)
    seen_mappings: set[tuple[str, str]] = set()
    for index, item in enumerate(mappings):
        mapping = _object(item, f"path_mapping[{index}]")
        _exact_fields(mapping, _MAPPING_FIELDS, f"path_mapping[{index}]")
        pair = (
            _absolute_path(mapping["source_prefix"], "source_prefix"),
            _absolute_path(mapping["execution_prefix"], "execution_prefix"),
        )
        if pair in seen_mappings:
            raise SchedulerProtocolError("path_mapping must not contain duplicates")
        seen_mappings.add(pair)
    for field in ("deploy_dir", "work_dir", "output_dir", "cache_dir"):
        _absolute_path(payload[field], field)
    if payload["container_engine"] != "apptainer":
        raise SchedulerProtocolError("scheduler protocol v2 requires Apptainer")
    containers = _array(payload["containers"], "containers", minimum=1, maximum=64)
    names: set[str] = set()
    for index, item in enumerate(containers):
        container = _object(item, f"containers[{index}]")
        _exact_fields(container, _CONTAINER_FIELDS, f"containers[{index}]")
        name = _identifier(container["name"], "container name")
        if name in names:
            raise SchedulerProtocolError("containers must have unique names")
        names.add(name)
        _text(container["image"], "container image", maximum=512)
        digest = container["digest"]
        if (
            not isinstance(digest, str)
            or not _OCI_DIGEST.fullmatch(digest)
            or digest == f"sha256:{'0' * 64}"
        ):
            raise SchedulerProtocolError("container digest must be sha256-bound")
        _absolute_path(container["local_path"], "container local_path")
        _digest(container["file_sha256"], "container file_sha256")
    minimum_free = payload["minimum_free_bytes"]
    if type(minimum_free) is not int or not 1 <= minimum_free <= 1024**5:
        raise SchedulerProtocolError("minimum_free_bytes is outside its strict range")
    if payload["network_disabled"] is not True:
        raise SchedulerProtocolError("network_disabled must be true")
    resume = payload["resume_run_id"]
    if resume is not None:
        _identifier(resume, "resume_run_id")


def _validate_deploy(payload: dict[str, Any]) -> None:
    for field in ("deployment_id", "preflight_id"):
        _identifier(payload[field], field)
    for field in ("project_hash", "bundle_hash"):
        _digest(payload[field], field)
    _absolute_path(payload["deployment_dir"], "deployment_dir")
    files = _array(
        payload["files"],
        "files",
        minimum=1,
        maximum=_MAX_DEPLOYMENT_FILES,
    )
    paths: set[str] = set()
    metadata: list[dict[str, str | int]] = []
    total = 0
    for index, item in enumerate(files):
        record = _object(item, f"files[{index}]")
        _exact_fields(record, _FILE_FIELDS, f"files[{index}]")
        path = _relative_path(record["path"], f"files[{index}].path")
        if path in paths:
            raise SchedulerProtocolError("files must not contain duplicate paths")
        paths.add(path)
        size = record["size"]
        if type(size) is not int or not 1 <= size <= _MAX_FILE_BYTES:
            raise SchedulerProtocolError("deployment file size is outside its strict range")
        expected_sha256 = _digest(record["sha256"], f"files[{index}].sha256")
        encoded = _text(
            record["content_base64"],
            f"files[{index}].content_base64",
            maximum=4 * ((_MAX_FILE_BYTES + 2) // 3),
        )
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SchedulerProtocolError("deployment file content_base64 is invalid") from exc
        if len(decoded) != size:
            raise SchedulerProtocolError("deployment file size does not match content_base64")
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise SchedulerProtocolError("deployment file content_base64 is not canonical")
        if hashlib.sha256(decoded).hexdigest() != expected_sha256:
            raise SchedulerProtocolError("deployment file content does not match sha256")
        metadata.append({"path": path, "sha256": expected_sha256, "size": size})
        total += size
        if total > 128 * 1024 * 1024:
            raise SchedulerProtocolError("deployment files exceed the protocol-v2 total limit")
    canonical_bundle_hash = _canonical_hash(
        sorted(metadata, key=lambda item: cast(str, item["path"]))
    )
    if canonical_bundle_hash != payload["bundle_hash"]:
        raise SchedulerProtocolError("deployment files do not match bundle_hash")


def _validate_run_mutation(operation: SchedulerOperation, payload: dict[str, Any]) -> None:
    for field in ("run_id", "preflight_id", "deployment_id"):
        _identifier(payload[field], field)
    for field in ("project_hash", "bundle_hash"):
        _digest(payload[field], field)
    _text(payload["preflight_token"], "preflight_token", maximum=256)
    if operation == "resume":
        resume = _identifier(payload["resume_run_id"], "resume_run_id")
        if resume == payload["run_id"]:
            raise SchedulerProtocolError("resume_run_id must identify an earlier run")
    _validate_approval(payload["approval"], payload)


def _validate_status(payload: dict[str, Any]) -> None:
    _identifier(payload["run_id"], "run_id")
    _digest(payload["project_hash"], "project_hash")
    _digest(payload["bundle_hash"], "bundle_hash")


def _validate_approval(value: Any, payload: dict[str, Any]) -> None:
    approval = _object(value, "approval")
    _exact_fields(approval, _APPROVAL_FIELDS, "approval")
    if approval["approved"] is not True:
        raise SchedulerProtocolError("approval.approved must be true")
    _identifier(approval["authorization_id"], "approval.authorization_id")
    _text(approval["actor"], "approval.actor", maximum=256)
    _utc_time(approval["approved_at"], "approval.approved_at")
    hashes = _object(approval["artifact_hashes"], "approval.artifact_hashes")
    _exact_fields(hashes, _APPROVAL_ARTIFACT_HASHES, "approval.artifact_hashes")
    for name, item in hashes.items():
        _digest(item, f"approval.artifact_hashes.{name}")
    if hashes["execution_profile"] != payload["profile_hash"]:
        raise SchedulerProtocolError("approval does not bind profile_hash")
    project_hash = _canonical_hash(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        }
    )
    if project_hash != payload["project_hash"]:
        raise SchedulerProtocolError("approval artifact hashes do not bind project_hash")
    bundle_hash = _digest(approval["bundle_hash"], "approval.bundle_hash")
    if bundle_hash != payload["bundle_hash"]:
        raise SchedulerProtocolError("approval does not bind bundle_hash")
    compatibility = _digest(approval["compatibility_hash"], "approval.compatibility_hash")
    expected_compatibility = _canonical_hash(
        {
            "bundle_hash": bundle_hash,
            "execution_profile": payload["profile_hash"],
            "project_hash": project_hash,
        }
    )
    if compatibility != expected_compatibility:
        raise SchedulerProtocolError("approval compatibility_hash is inconsistent")
    _identifier(approval["key_id"], "approval.key_id")
    _digest(approval["signature"], "approval.signature")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SchedulerProtocolError(f"{label} must be an object with string keys")
    return cast(dict[str, Any], value)


def _exact_fields(value: dict[str, Any], fields: frozenset[str], label: str) -> None:
    if set(value) != fields:
        raise SchedulerProtocolError(f"{label} fields do not match the exact contract")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SchedulerProtocolError(f"{label} must be one safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value) or value == "0" * 64:
        raise SchedulerProtocolError(f"{label} must be one non-placeholder lowercase SHA-256")
    return value


def _text(value: Any, label: str, *, maximum: int = _MAX_TEXT_BYTES) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SchedulerProtocolError(f"{label} must be bounded safe text")
    return value


def _absolute_path(value: Any, label: str) -> str:
    text = _text(value, label, maximum=_MAX_PATH_BYTES)
    path = PurePosixPath(text)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise SchedulerProtocolError(f"{label} must be a non-root absolute POSIX path")
    if str(path) != text:
        raise SchedulerProtocolError(f"{label} must be a canonical POSIX path")
    return text


def _relative_path(value: Any, label: str) -> str:
    text = _text(value, label, maximum=_MAX_PATH_BYTES)
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or ".." in path.parts or str(path) != text:
        raise SchedulerProtocolError(f"{label} must be one canonical relative POSIX path")
    return text


def _array(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_ARRAY_ITEMS,
) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise SchedulerProtocolError(f"{label} must be a bounded array")
    return value


def _path_array(value: Any, label: str) -> tuple[str, ...]:
    values = _array(value, label, minimum=1)
    paths = tuple(_absolute_path(item, label) for item in values)
    if len(paths) != len(set(paths)):
        raise SchedulerProtocolError(f"{label} must not contain duplicates")
    return paths


def _utc_time(value: Any, label: str) -> str:
    text = _text(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchedulerProtocolError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SchedulerProtocolError(f"{label} must include a timezone")
    parsed.astimezone(timezone.utc)  # noqa: UP017 - bioinfo supports Python 3.10.
    return text


def _submit_time(value: Any) -> str:
    if not isinstance(value, str) or not _SUBMIT_TIME.fullmatch(value):
        raise SchedulerProtocolError("submitted_at must use YYYY-MM-DDTHH:MM:SS")
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise SchedulerProtocolError("submitted_at is not a real calendar timestamp") from exc
    return value


def _job_id(value: Any) -> str:
    if not isinstance(value, str) or not _JOB_ID.fullmatch(value):
        raise SchedulerProtocolError("job_id must be one canonical positive decimal")
    if int(value) > _MAX_JOB_ID:
        raise SchedulerProtocolError("job_id is outside the supported Slurm range")
    return value


def _optional_byte(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 255:
        raise SchedulerProtocolError(f"{label} must be null or an integer from 0 to 255")
    return value


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _reject_excessive_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_NESTING:
                raise ValueError("JSON nesting exceeds the supported limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("JSON delimiters are unbalanced")
    if depth != 0 or in_string:
        raise ValueError("JSON structure is incomplete")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


__all__ = [
    "PROTOCOL_VERSION",
    "SchedulerProtocolError",
    "SchedulerRequest",
    "SlurmRunEvidence",
    "canonical_hmac_envelope_bytes",
    "decode_json_line",
    "parse_request",
    "parse_slurm_run_evidence",
]
