"""Dormant trusted run reservation and at-most-once start boundary for M7.

Protocol version 1 never imports this module.  A validated scheduler-v2
submit/resume request is authenticated here, reduced to a secret-free binding,
and reserved below a separate owner-only namespace.  The raw capability token,
approval signature, and HMAC key are never serialized.  A compute bootstrap may
later create exactly one start intent and receive one live process/thread-bound
permit; restart never recreates that permit.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import stat
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import InitVar, dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, cast

from .scheduler_clock import SchedulerClock, SystemSchedulerClock
from .scheduler_config_loader import (
    TrustedSchedulerConfig,
    verify_scheduler_config_file,
    verify_scheduler_root,
)
from .scheduler_protocol import (
    SchedulerProtocolError,
    SchedulerRequest,
    canonical_hmac_envelope_bytes,
    parse_request,
)
from .scheduler_state import (
    SchedulerPreflightStore,
    SchedulerStateBusyError,
    SchedulerStateCommitUnknown,
    SchedulerStateError,
    SchedulerStateSnapshot,
    _create_record,
    _decode_canonical_object,
    _nonblocking_flock,
    _open_created_private_directory,
    _open_lock_file,
    _open_private_directory,
    _open_state_root,
    _read_private_bytes,
    _require_durable_directory,
)

if TYPE_CHECKING:
    from .scheduler_workload import SchedulerWorkloadPlan

SCHEDULER_RUN_SCHEMA_VERSION = "1.1"
SCHEDULER_RUN_NAMESPACE = "scheduler-runs-v1"

_CREATE_LOCK = ".create.lock"
_RUN_LOCK = "lease.lock"
_IDENTITY_FILE = "identity.json"
_START_INTENT_FILE = "start.intent.json"
_MAX_IDENTITY_BYTES = 8 * 1024 * 1024
_MAX_START_INTENT_BYTES = 64 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TOKEN = re.compile(r"[0-9a-f]{64}", re.ASCII)

_VERIFIED_AUTHORITY = object()
_SNAPSHOT_AUTHORITY = object()
_PERMIT_AUTHORITY = object()

RunOperation = Literal["submit", "resume"]
BootstrapVerifier = Callable[[], None]


class SchedulerRunError(RuntimeError):
    """Base class for sanitized scheduler-run state failures."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


class SchedulerRunContractError(ValueError):
    """A caller value is outside the fixed dormant run contract."""


class SchedulerRunConflictError(SchedulerRunError):
    """An immutable run reservation or start intent conflicts."""


class SchedulerRunInvalidError(SchedulerRunError):
    """Durable run bytes or filesystem identities are unsafe."""


class SchedulerRunBusyError(SchedulerRunError):
    """Another process owns the run transition lease."""


class SchedulerRunPreconditionError(SchedulerRunError):
    """Trusted configuration, preflight state, or bootstrap proof changed."""


class SchedulerRunCommitUnknown(SchedulerRunError):
    """A create-only run record may or may not have committed."""


class SchedulerStartPermitError(SchedulerRunError):
    """A start action lacks the one live run-bound permit."""


@dataclass(frozen=True, order=True)
class SchedulerDeploymentFile:
    """One exact sealed deployment file required on the compute node."""

    path: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        _relative_path(self.path)
        _strict_int(self.size, "deployment file size", 1, 32 * 1024 * 1024)
        _digest(self.sha256, "deployment file sha256")

    def as_record(self) -> dict[str, str | int]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class SchedulerDeploymentBinding:
    """Immutable deployed bundle identity copied into the run reservation."""

    deployment_id: str
    deployment_dir: str
    directory_device: int
    directory_inode: int
    directory_owner: int
    directory_group: int
    directory_mode: int
    bundle_hash: str
    files: tuple[SchedulerDeploymentFile, ...]

    def __post_init__(self) -> None:
        _identifier(self.deployment_id, "deployment_id")
        _absolute_path(self.deployment_dir, "deployment_dir")
        for label, value in (
            ("directory_device", self.directory_device),
            ("directory_inode", self.directory_inode),
            ("directory_owner", self.directory_owner),
            ("directory_group", self.directory_group),
        ):
            _strict_int(value, label, 0, 2**63 - 1)
        if self.directory_mode != 0o500:
            raise SchedulerRunContractError("deployment directory must be sealed mode 0500")
        _digest(self.bundle_hash, "bundle_hash")
        if (
            not isinstance(self.files, tuple)
            or not self.files
            or len(self.files) > 1024
            or any(not isinstance(item, SchedulerDeploymentFile) for item in self.files)
            or tuple(sorted(self.files)) != self.files
            or len({item.path for item in self.files}) != len(self.files)
        ):
            raise SchedulerRunContractError(
                "deployment files must be one sorted unique non-empty tuple"
            )
        if _canonical_hash([item.as_record() for item in self.files]) != self.bundle_hash:
            raise SchedulerRunContractError("deployment files do not bind bundle_hash")

    @property
    def directory_identity(self) -> tuple[int, int, int, int, int]:
        return (
            self.directory_device,
            self.directory_inode,
            self.directory_owner,
            self.directory_group,
            self.directory_mode,
        )

    def as_record(self) -> dict[str, Any]:
        return {
            "deployment_id": self.deployment_id,
            "deployment_dir": self.deployment_dir,
            "directory_device": self.directory_device,
            "directory_inode": self.directory_inode,
            "directory_owner": self.directory_owner,
            "directory_group": self.directory_group,
            "directory_mode": self.directory_mode,
            "bundle_hash": self.bundle_hash,
            "files": [item.as_record() for item in self.files],
        }


@dataclass(frozen=True)
class VerifiedSchedulerRunRequest:
    """Store-owned authenticated run binding with transient token possession."""

    _authority: InitVar[object]
    operation: RunOperation
    run_id: str
    preflight_id: str
    preflight_request_sha256: str
    capability_token_hash: str
    capability_issued_at: int
    capability_expires_at: int
    deployment: SchedulerDeploymentBinding
    profile_id: str
    profile_hash: str
    scheduler_policy_hash: str
    project_hash: str
    authorization_id: str
    actor: str
    approved_at: str
    key_id: str
    approval_artifact_hashes: Mapping[str, str]
    compatibility_hash: str
    request_binding_sha256: str
    consumer_binding_hash: str
    resume_run_id: str | None
    config_sha256: str
    contract_sha256: str
    _preflight_token: str = field(repr=False, compare=False)
    _config_token: object = field(repr=False, compare=False)

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _VERIFIED_AUTHORITY:
            raise SchedulerRunContractError("verified scheduler run requests are internal")
        if self.operation not in {"submit", "resume"}:
            raise SchedulerRunContractError("scheduler run operation is invalid")
        for value, label in (
            (self.run_id, "run_id"),
            (self.preflight_id, "preflight_id"),
            (self.profile_id, "profile_id"),
            (self.authorization_id, "authorization_id"),
            (self.key_id, "key_id"),
        ):
            _identifier(value, label)
        _actor(self.actor)
        _approved_at(self.approved_at)
        for value, label in (
            (self.preflight_request_sha256, "preflight_request_sha256"),
            (self.capability_token_hash, "capability token hash"),
            (self.profile_hash, "profile_hash"),
            (self.scheduler_policy_hash, "scheduler_policy_hash"),
            (self.project_hash, "project_hash"),
            (self.compatibility_hash, "compatibility_hash"),
            (self.request_binding_sha256, "request_binding_sha256"),
            (self.consumer_binding_hash, "consumer_binding_hash"),
            (self.config_sha256, "config_sha256"),
            (self.contract_sha256, "contract_sha256"),
        ):
            _digest(value, label)
        _strict_int(self.capability_issued_at, "capability issued_at", 0, 2**63 - 1)
        _strict_int(
            self.capability_expires_at,
            "capability expires_at",
            self.capability_issued_at + 1,
            2**63 - 1,
        )
        if not isinstance(self.deployment, SchedulerDeploymentBinding):
            raise SchedulerRunContractError("verified run requires a deployment binding")
        if not isinstance(self.approval_artifact_hashes, Mapping) or set(
            self.approval_artifact_hashes
        ) != {
            "dataset_manifest",
            "pipeline_spec",
            "execution_plan",
            "software_lock",
            "execution_profile",
            "validation_report",
            "test_report",
            "preflight_report",
        }:
            raise SchedulerRunContractError("approval artifact hashes are incomplete")
        for name, value in self.approval_artifact_hashes.items():
            _digest(value, f"approval artifact {name}")
        if self.resume_run_id is not None:
            _identifier(self.resume_run_id, "resume_run_id")
        if (self.operation == "resume") != (self.resume_run_id is not None):
            raise SchedulerRunContractError("resume binding conflicts with operation")
        _raw_token(self._preflight_token)

    def as_record(self) -> dict[str, Any]:
        """Return the exact durable identity without raw token or signature."""

        return {
            "schema_version": SCHEDULER_RUN_SCHEMA_VERSION,
            "operation": self.operation,
            "run_id": self.run_id,
            "preflight_id": self.preflight_id,
            "preflight_request_sha256": self.preflight_request_sha256,
            "capability_token_hash": self.capability_token_hash,
            "capability_issued_at": self.capability_issued_at,
            "capability_expires_at": self.capability_expires_at,
            "deployment": self.deployment.as_record(),
            "profile_id": self.profile_id,
            "profile_hash": self.profile_hash,
            "scheduler_policy_hash": self.scheduler_policy_hash,
            "project_hash": self.project_hash,
            "authorization_id": self.authorization_id,
            "actor": self.actor,
            "approved_at": self.approved_at,
            "key_id": self.key_id,
            "approval_artifact_hashes": dict(sorted(self.approval_artifact_hashes.items())),
            "compatibility_hash": self.compatibility_hash,
            "request_binding_sha256": self.request_binding_sha256,
            "consumer_binding_hash": self.consumer_binding_hash,
            "resume_run_id": self.resume_run_id,
            "config_sha256": self.config_sha256,
            "contract_sha256": self.contract_sha256,
        }


@dataclass(frozen=True)
class SchedulerRunSnapshot:
    """Opaque immutable replay of one exact run reservation."""

    _authority: InitVar[object]
    run_id: str
    identity_sha256: str
    identity: Mapping[str, Any]
    deployment: SchedulerDeploymentBinding
    preflight_id: str
    preflight_request_sha256: str
    actor: str
    consumer_binding_hash: str
    capability_token_hash: str
    _store_token: object = field(repr=False, compare=False)

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _SNAPSHOT_AUTHORITY:
            raise SchedulerRunContractError("scheduler run snapshots are store-owned")
        _identifier(self.run_id, "run_id")
        _digest(self.identity_sha256, "identity_sha256")
        if not isinstance(self.identity, Mapping):
            raise SchedulerRunContractError("scheduler run identity is invalid")
        if _canonical_record_hash(self.identity) != self.identity_sha256:
            raise SchedulerRunContractError("scheduler run snapshot identity hash changed")
        if not isinstance(self.deployment, SchedulerDeploymentBinding):
            raise SchedulerRunContractError("scheduler run deployment is invalid")
        _identifier(self.preflight_id, "preflight_id")
        _digest(self.preflight_request_sha256, "preflight_request_sha256")
        _actor(self.actor)
        _digest(self.consumer_binding_hash, "consumer_binding_hash")
        _digest(self.capability_token_hash, "capability_token_hash")


@dataclass
class _StartSession:
    store_token: object
    pid: int
    thread: threading.Thread
    run_id: str
    identity_sha256: str
    start_intent_sha256: str
    workload_binding_sha256: str
    workload_batch_sha256: str
    run_fd: int
    lock_fd: int
    active: bool = True
    consumed: bool = False
    guard: threading.Lock = field(default_factory=threading.Lock)


@dataclass(frozen=True)
class SchedulerStartPermit:
    """One live non-reconstructible permit for the fixed bootstrap continuation."""

    _authority: InitVar[object]
    run_id: str
    identity_sha256: str
    start_intent_sha256: str
    workload_binding_sha256: str
    workload_batch_sha256: str
    _session: _StartSession = field(repr=False, compare=False)

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _PERMIT_AUTHORITY:
            raise SchedulerRunContractError("scheduler start permits are store-owned")
        _identifier(self.run_id, "run_id")
        _digest(self.identity_sha256, "identity_sha256")
        _digest(self.start_intent_sha256, "start_intent_sha256")
        _digest(self.workload_binding_sha256, "workload_binding_sha256")
        _digest(self.workload_batch_sha256, "workload_batch_sha256")


def verify_scheduler_run_request(
    request: SchedulerRequest,
    config: TrustedSchedulerConfig,
    deployment: SchedulerDeploymentBinding,
    preflight: SchedulerStateSnapshot,
) -> VerifiedSchedulerRunRequest:
    """Authenticate one dormant v2 run request and derive its secret-free binding."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerRunContractError("trusted scheduler config-v2 is required")
    if not isinstance(deployment, SchedulerDeploymentBinding):
        raise SchedulerRunContractError("trusted deployment binding is required")
    if not isinstance(preflight, SchedulerStateSnapshot):
        raise SchedulerRunContractError("durable scheduler preflight snapshot is required")
    try:
        validated = parse_request(
            {
                "protocol_version": request.protocol_version,
                "request_id": request.request_id,
                "operation": request.operation,
                "payload": _thaw(request.payload),
            }
        )
        signed_bytes = canonical_hmac_envelope_bytes(validated)
    except (AttributeError, SchedulerProtocolError, TypeError, ValueError) as exc:
        raise SchedulerRunContractError("scheduler run request is not valid protocol-v2") from exc
    if validated.operation not in {"submit", "resume"}:
        raise SchedulerRunContractError("only submit and resume can reserve a scheduler run")
    payload = cast(dict[str, Any], _thaw(validated.payload))
    approval = cast(dict[str, Any], payload["approval"])
    signature = approval["signature"]
    expected_signature = hmac.new(
        config.contract.approval_hmac_key,
        signed_bytes,
        hashlib.sha256,
    ).hexdigest()
    if (
        approval["key_id"] != config.contract.approval_key_id
        or not isinstance(signature, str)
        or not hmac.compare_digest(signature, expected_signature)
    ):
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_APPROVAL_INVALID",
            "scheduler run approval could not be authenticated",
        )
    state = preflight.state
    capability = state.capability
    token = _raw_token(payload["preflight_token"])
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    actor = _actor(approval["actor"])
    limits = config.contract.limits
    if (
        len(deployment.files) > limits.max_deployment_files
        or any(item.size > limits.max_file_bytes for item in deployment.files)
        or sum(item.size for item in deployment.files) > limits.max_deployment_bytes
    ):
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_DEPLOYMENT_BUDGET_EXCEEDED",
            "scheduler deployment binding exceeds trusted config-v2 limits",
        )
    _verify_deployment_directory_binding(config, deployment)
    if (
        state.phase != "passed"
        or capability is None
        or capability.expired
        or not hmac.compare_digest(capability.token_hash, token_hash)
        or payload["preflight_id"] != state.manifest.preflight_id
        or payload["profile_id"] != config.contract.profile_id
        or payload["profile_hash"] != config.contract.profile_hash
        or payload["scheduler_policy_hash"] != config.scheduler_policy_hash
        or payload["profile_id"] != state.manifest.profile_id
        or payload["profile_hash"] != state.manifest.profile_hash
        or payload["scheduler_policy_hash"] != state.manifest.scheduler_policy_hash
        or payload["project_hash"] != state.manifest.project_hash
        or payload["deployment_id"] != deployment.deployment_id
        or payload["bundle_hash"] != deployment.bundle_hash
        or deployment.deployment_dir != state.manifest.deploy_dir
    ):
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_BINDING_MISMATCH",
            "scheduler run request does not bind trusted preflight and deployment state",
        )
    resume_run_id = payload.get("resume_run_id") if validated.operation == "resume" else None
    request_binding = hashlib.sha256(signed_bytes).hexdigest()
    approval_hashes = dict(sorted(cast(dict[str, str], approval["artifact_hashes"]).items()))
    consumer_payload = {
        "domain": "easy-pipe.scheduler-run.consumer-binding.v1",
        "operation": validated.operation,
        "run_id": payload["run_id"],
        "preflight_id": payload["preflight_id"],
        "preflight_request_sha256": preflight.request_sha256,
        "capability_token_hash": capability.token_hash,
        "capability_issued_at": capability.issued_at,
        "capability_expires_at": capability.expires_at,
        "deployment": deployment.as_record(),
        "profile_id": payload["profile_id"],
        "profile_hash": payload["profile_hash"],
        "scheduler_policy_hash": payload["scheduler_policy_hash"],
        "project_hash": payload["project_hash"],
        "bundle_hash": payload["bundle_hash"],
        "authorization_id": approval["authorization_id"],
        "actor": actor,
        "approved_at": approval["approved_at"],
        "key_id": approval["key_id"],
        "approval_artifact_hashes": approval_hashes,
        "compatibility_hash": approval["compatibility_hash"],
        "request_binding_sha256": request_binding,
        "resume_run_id": resume_run_id,
    }
    consumer_binding = _canonical_hash(consumer_payload)
    if capability.consumed and (
        capability.consumed_by != actor or capability.consumer_binding_hash != consumer_binding
    ):
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_CAPABILITY_CONFLICT",
            "consumed capability belongs to a different scheduler run binding",
        )
    return VerifiedSchedulerRunRequest(
        _authority=_VERIFIED_AUTHORITY,
        operation=cast(RunOperation, validated.operation),
        run_id=payload["run_id"],
        preflight_id=payload["preflight_id"],
        preflight_request_sha256=preflight.request_sha256,
        capability_token_hash=capability.token_hash,
        capability_issued_at=capability.issued_at,
        capability_expires_at=capability.expires_at,
        deployment=deployment,
        profile_id=payload["profile_id"],
        profile_hash=payload["profile_hash"],
        scheduler_policy_hash=payload["scheduler_policy_hash"],
        project_hash=payload["project_hash"],
        authorization_id=approval["authorization_id"],
        actor=actor,
        approved_at=approval["approved_at"],
        key_id=approval["key_id"],
        approval_artifact_hashes=MappingProxyType(approval_hashes),
        compatibility_hash=approval["compatibility_hash"],
        request_binding_sha256=request_binding,
        consumer_binding_hash=consumer_binding,
        resume_run_id=resume_run_id,
        config_sha256=config.config_sha256,
        contract_sha256=config.contract_sha256,
        _preflight_token=token,
        _config_token=config,
    )


@dataclass(frozen=True)
class SchedulerRunStore:
    """Owner-only create/load/start store beneath one trusted config-v2 root."""

    config: TrustedSchedulerConfig
    clock: SchedulerClock = field(
        default_factory=SystemSchedulerClock,
        repr=False,
        compare=False,
    )
    _store_token: object = field(default_factory=object, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.config, TrustedSchedulerConfig):
            raise SchedulerRunContractError("scheduler run store requires trusted config-v2")
        if not callable(getattr(self.clock, "sample", None)):
            raise SchedulerRunContractError("scheduler run store requires a trusted clock")

    def reserve_and_consume(
        self,
        verified: VerifiedSchedulerRunRequest,
    ) -> SchedulerRunSnapshot:
        """Reserve identity first, then consume only its exact hidden capability."""

        snapshot = self.reserve(verified)
        preflight_store = SchedulerPreflightStore(self.config, clock=self.clock)
        try:
            preflight = preflight_store.load(
                snapshot.preflight_id,
                request_sha256=snapshot.preflight_request_sha256,
            )
            capability = preflight.state.capability
            if capability is not None and capability.consumed:
                self._require_consumed_preflight(snapshot, preflight)
                return snapshot
            consumed = preflight_store.consume_capability(
                preflight,
                token=verified._preflight_token,
                consumed_by=verified.actor,
                consumer_binding_hash=verified.consumer_binding_hash,
            )
        except SchedulerStateBusyError as exc:
            raise SchedulerRunBusyError(
                "SCHEDULER_RUN_PREFLIGHT_BUSY",
                "the scheduler capability transition is temporarily leased",
            ) from exc
        except SchedulerStateCommitUnknown as exc:
            raise SchedulerRunCommitUnknown(
                "SCHEDULER_RUN_CAPABILITY_COMMIT_UNKNOWN",
                "capability consumption may have committed; restart must replay it",
            ) from exc
        except SchedulerStateError as exc:
            raise SchedulerRunPreconditionError(
                "SCHEDULER_RUN_CAPABILITY_UNAVAILABLE",
                "the exact scheduler capability could not be consumed safely",
            ) from exc
        self._require_consumed_preflight(snapshot, consumed)
        return snapshot

    def reserve(self, verified: VerifiedSchedulerRunRequest) -> SchedulerRunSnapshot:
        """Create or exactly replay one immutable secret-free run reservation."""

        if not isinstance(verified, VerifiedSchedulerRunRequest):
            raise SchedulerRunContractError("verified scheduler run request is required")
        if verified._config_token is not self.config:
            raise SchedulerRunContractError("verified scheduler run belongs to another config")
        expected = verified.as_record()
        root = namespace = lock = run = -1
        try:
            root, namespace = self._open_namespace(create=True)
            lock = _open_lock_file(namespace, _CREATE_LOCK, create=True)
            with _nonblocking_flock(lock, "SCHEDULER_RUN_CREATE_BUSY"):
                try:
                    os.mkdir(verified.run_id, 0o700, dir_fd=namespace)
                except FileExistsError:
                    run = _open_private_directory(namespace, verified.run_id)
                    observed = self._read_identity(run)
                    if observed != expected:
                        raise SchedulerRunConflictError(
                            "SCHEDULER_RUN_ALREADY_RESERVED",
                            "the run identifier is reserved with different bindings",
                        ) from None
                    return self._snapshot(observed)
                except OSError as exc:
                    raise SchedulerRunCommitUnknown(
                        "SCHEDULER_RUN_DIRECTORY_COMMIT_UNKNOWN",
                        "the create-only run directory may be incomplete",
                    ) from exc
                run = _open_created_private_directory(namespace, verified.run_id)
                _require_durable_directory(namespace)
                _open_and_close_run_lock(run, create=True)
                _create_record(run, _IDENTITY_FILE, expected, _MAX_IDENTITY_BYTES)
                _require_durable_directory(run)
                _require_durable_directory(namespace)
                observed = self._read_identity(run)
                if observed != expected:
                    raise SchedulerRunCommitUnknown(
                        "SCHEDULER_RUN_RESERVATION_POST_COMMIT_UNKNOWN",
                        "run reservation did not replay to the expected identity",
                    )
                return self._snapshot(observed)
        except SchedulerRunError:
            raise
        except SchedulerStateBusyError as exc:
            raise SchedulerRunBusyError(exc.reason_code, str(exc)) from exc
        except SchedulerStateCommitUnknown as exc:
            raise SchedulerRunCommitUnknown(exc.reason_code, str(exc)) from exc
        except SchedulerStateError as exc:
            raise SchedulerRunInvalidError(exc.reason_code, str(exc)) from exc
        finally:
            for descriptor in (run, lock, namespace, root):
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def load(self, run_id: str) -> SchedulerRunSnapshot:
        """Replay one exact reservation without reconstructing a token or permit."""

        selected = _identifier(run_id, "run_id")
        root = namespace = run = -1
        try:
            root, namespace = self._open_namespace(create=False)
            run = _open_private_directory(namespace, selected)
            return self._snapshot(self._read_identity(run))
        except FileNotFoundError as exc:
            raise SchedulerRunInvalidError(
                "SCHEDULER_RUN_NOT_FOUND",
                "the scheduler run reservation does not exist",
            ) from exc
        except SchedulerRunError:
            raise
        except SchedulerStateError as exc:
            raise SchedulerRunInvalidError(exc.reason_code, str(exc)) from exc
        except OSError as exc:
            raise SchedulerRunInvalidError(
                "SCHEDULER_RUN_STATE_INVALID",
                "the scheduler run reservation cannot be opened safely",
            ) from exc
        finally:
            for descriptor in (run, namespace, root):
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def load_consumed_preflight(self, snapshot: SchedulerRunSnapshot) -> SchedulerStateSnapshot:
        """Replay and exactly bind the consumed capability used by this run."""

        selected = self._bound_snapshot(snapshot)
        try:
            preflight = SchedulerPreflightStore(self.config).load(
                selected.preflight_id,
                request_sha256=selected.preflight_request_sha256,
            )
        except SchedulerStateBusyError as exc:
            raise SchedulerRunBusyError(
                "SCHEDULER_RUN_PREFLIGHT_BUSY",
                "the consumed scheduler preflight is temporarily leased",
            ) from exc
        except SchedulerStateError as exc:
            raise SchedulerRunPreconditionError(
                "SCHEDULER_RUN_PREFLIGHT_UNAVAILABLE",
                "the consumed scheduler preflight cannot be replayed safely",
            ) from exc
        self._require_consumed_preflight(selected, preflight)
        return preflight

    @staticmethod
    def _require_consumed_preflight(
        snapshot: SchedulerRunSnapshot,
        preflight: SchedulerStateSnapshot,
    ) -> None:
        capability = preflight.state.capability
        if (
            preflight.state.phase != "passed"
            or capability is None
            or not capability.consumed
            or capability.expired
            or capability.token_hash != snapshot.capability_token_hash
            or capability.consumed_by != snapshot.actor
            or capability.consumer_binding_hash != snapshot.consumer_binding_hash
        ):
            raise SchedulerRunPreconditionError(
                "SCHEDULER_RUN_CAPABILITY_NOT_CONSUMED",
                "run reservation is not backed by the exact consumed capability",
            )

    @contextlib.contextmanager
    def claim_start(
        self,
        snapshot: SchedulerRunSnapshot,
        preflight: SchedulerStateSnapshot,
        verifier: BootstrapVerifier,
        *,
        workload: SchedulerWorkloadPlan,
    ) -> Iterator[SchedulerStartPermit]:
        """Verify artifacts, bind one workload, and yield one live start permit."""

        selected = self._bound_snapshot(snapshot)
        if not callable(verifier):
            raise SchedulerRunContractError("bootstrap verifier callback is required")
        current_preflight = self.load_consumed_preflight(selected)
        if (
            not isinstance(preflight, SchedulerStateSnapshot)
            or preflight.request_sha256 != current_preflight.request_sha256
            or preflight.revision != current_preflight.revision
            or preflight.journal_sha256 != current_preflight.journal_sha256
            or preflight.state != current_preflight.state
        ):
            raise SchedulerRunConflictError(
                "SCHEDULER_RUN_PREFLIGHT_STALE",
                "the consumed preflight snapshot is stale or belongs to another run",
            )
        binding_sha256, batch_sha256 = _validated_workload_hashes(
            workload,
            selected,
            current_preflight,
        )
        root = namespace = run = lock = -1
        session: _StartSession | None = None
        try:
            root, namespace = self._open_namespace(create=False)
            run = _open_private_directory(namespace, selected.run_id)
            lock = _open_lock_file(run, _RUN_LOCK, create=False)
            try:
                lease = _nonblocking_flock(lock, "SCHEDULER_RUN_START_BUSY")
                lease.__enter__()
            except SchedulerStateError as exc:
                raise SchedulerRunBusyError(exc.reason_code, str(exc)) from exc
            observed = self._read_identity(run)
            if _canonical_record_hash(observed) != selected.identity_sha256:
                raise SchedulerRunConflictError(
                    "SCHEDULER_RUN_SNAPSHOT_CONFLICT",
                    "the run reservation changed after it was loaded",
                )
            try:
                _read_private_bytes(run, _START_INTENT_FILE, _MAX_START_INTENT_BYTES)
            except FileNotFoundError:
                pass
            except SchedulerStateError as exc:
                raise SchedulerRunInvalidError(
                    "SCHEDULER_RUN_START_INTENT_INVALID",
                    "an existing scheduler start intent is unsafe or incomplete",
                ) from exc
            else:
                raise SchedulerRunConflictError(
                    "SCHEDULER_RUN_START_ALREADY_CLAIMED",
                    "the run start intent is already burned",
                )
            verifier()
            refreshed = self.load_consumed_preflight(selected)
            if (
                refreshed.revision != current_preflight.revision
                or refreshed.journal_sha256 != current_preflight.journal_sha256
                or refreshed.state != current_preflight.state
            ):
                raise SchedulerRunPreconditionError(
                    "SCHEDULER_RUN_PREFLIGHT_CHANGED",
                    "consumed preflight state changed during compute verification",
                )
            binding_sha256, batch_sha256 = _validated_workload_hashes(
                workload,
                selected,
                refreshed,
            )
            capability = refreshed.state.capability
            assert capability is not None and capability.consumed_at is not None
            intent = {
                "schema_version": SCHEDULER_RUN_SCHEMA_VERSION,
                "run_id": selected.run_id,
                "identity_sha256": selected.identity_sha256,
                "preflight_id": selected.preflight_id,
                "preflight_request_sha256": selected.preflight_request_sha256,
                "preflight_revision": refreshed.revision,
                "preflight_journal_sha256": refreshed.journal_sha256,
                "capability_token_hash": capability.token_hash,
                "capability_binding_hash": capability.binding_hash,
                "consumed_by": capability.consumed_by,
                "consumer_binding_hash": capability.consumer_binding_hash,
                "consumed_at": capability.consumed_at,
                "workload_binding_sha256": binding_sha256,
                "workload_batch_sha256": batch_sha256,
            }
            try:
                intent_sha = _create_record(
                    run,
                    _START_INTENT_FILE,
                    intent,
                    _MAX_START_INTENT_BYTES,
                )
            except SchedulerStateCommitUnknown as exc:
                raise SchedulerRunCommitUnknown(exc.reason_code, str(exc)) from exc
            except SchedulerStateError as exc:
                raise SchedulerRunConflictError(exc.reason_code, str(exc)) from exc
            try:
                raw_intent = _read_private_bytes(
                    run,
                    _START_INTENT_FILE,
                    _MAX_START_INTENT_BYTES,
                )
                replayed = _decode_canonical_object(raw_intent)
            except SchedulerStateError as exc:
                raise SchedulerRunCommitUnknown(
                    "SCHEDULER_RUN_START_POST_COMMIT_UNKNOWN",
                    "start intent could not be replayed safely",
                ) from exc
            if replayed != intent or hashlib.sha256(raw_intent).hexdigest() != intent_sha:
                raise SchedulerRunCommitUnknown(
                    "SCHEDULER_RUN_START_POST_COMMIT_UNKNOWN",
                    "start intent did not replay to the expected state",
                )
            session = _StartSession(
                store_token=self._store_token,
                pid=os.getpid(),
                thread=threading.current_thread(),
                run_id=selected.run_id,
                identity_sha256=selected.identity_sha256,
                start_intent_sha256=intent_sha,
                workload_binding_sha256=binding_sha256,
                workload_batch_sha256=batch_sha256,
                run_fd=run,
                lock_fd=lock,
            )
            permit = SchedulerStartPermit(
                _authority=_PERMIT_AUTHORITY,
                run_id=selected.run_id,
                identity_sha256=selected.identity_sha256,
                start_intent_sha256=intent_sha,
                workload_binding_sha256=binding_sha256,
                workload_batch_sha256=batch_sha256,
                _session=session,
            )
            yield permit
        finally:
            if session is not None:
                with session.guard:
                    session.active = False
            if "lease" in locals():
                with contextlib.suppress(BaseException):
                    lease.__exit__(None, None, None)
            for descriptor in (lock, run, namespace, root):
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def _bound_snapshot(self, snapshot: SchedulerRunSnapshot) -> SchedulerRunSnapshot:
        if (
            not isinstance(snapshot, SchedulerRunSnapshot)
            or snapshot._store_token is not self._store_token
        ):
            raise SchedulerRunContractError("scheduler run snapshot belongs to another store")
        return snapshot

    def _open_namespace(self, *, create: bool) -> tuple[int, int]:
        root = -1
        try:
            verify_scheduler_config_file(self.config)
            verify_scheduler_root(self.config, "state")
            root = _open_state_root(self.config)
            if create:
                try:
                    os.mkdir(SCHEDULER_RUN_NAMESPACE, 0o700, dir_fd=root)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise SchedulerRunCommitUnknown(
                        "SCHEDULER_RUN_NAMESPACE_COMMIT_UNKNOWN",
                        "the scheduler run namespace may be incomplete",
                    ) from exc
            namespace = _open_private_directory(root, SCHEDULER_RUN_NAMESPACE)
            _require_durable_directory(root)
            _require_durable_directory(namespace)
            return root, namespace
        except SchedulerRunError:
            if root >= 0:
                os.close(root)
            raise
        except (OSError, SchedulerStateError, ValueError) as exc:
            if root >= 0:
                os.close(root)
            raise SchedulerRunPreconditionError(
                "SCHEDULER_RUN_NAMESPACE_UNAVAILABLE",
                "the trusted scheduler run namespace is unavailable",
            ) from exc

    def _read_identity(self, run: int) -> dict[str, Any]:
        try:
            raw = _read_private_bytes(run, _IDENTITY_FILE, _MAX_IDENTITY_BYTES)
            value = _decode_canonical_object(raw)
            _parse_identity(value)
            if (
                value["config_sha256"] != self.config.config_sha256
                or value["contract_sha256"] != self.config.contract_sha256
                or value["profile_id"] != self.config.contract.profile_id
                or value["profile_hash"] != self.config.contract.profile_hash
                or value["scheduler_policy_hash"] != self.config.scheduler_policy_hash
            ):
                raise SchedulerRunInvalidError(
                    "SCHEDULER_RUN_CONFIG_BINDING_INVALID",
                    "the scheduler run identity belongs to another trusted config",
                )
            return value
        except FileNotFoundError as exc:
            raise SchedulerRunInvalidError(
                "SCHEDULER_RUN_IDENTITY_MISSING",
                "the create-only run reservation is incomplete",
            ) from exc
        except SchedulerRunError:
            raise
        except (SchedulerStateError, ValueError) as exc:
            raise SchedulerRunInvalidError(
                "SCHEDULER_RUN_IDENTITY_INVALID",
                "the create-only run identity is unsafe or malformed",
            ) from exc

    def _snapshot(self, identity: Mapping[str, Any]) -> SchedulerRunSnapshot:
        deployment = _parse_deployment(identity["deployment"])
        return SchedulerRunSnapshot(
            _authority=_SNAPSHOT_AUTHORITY,
            run_id=cast(str, identity["run_id"]),
            identity_sha256=_canonical_record_hash(identity),
            identity=MappingProxyType(_freeze(cast(dict[str, Any], identity))),
            deployment=deployment,
            preflight_id=cast(str, identity["preflight_id"]),
            preflight_request_sha256=cast(str, identity["preflight_request_sha256"]),
            actor=cast(str, identity["actor"]),
            consumer_binding_hash=cast(str, identity["consumer_binding_hash"]),
            capability_token_hash=cast(str, identity["capability_token_hash"]),
            _store_token=self._store_token,
        )


def consume_start_permit(
    permit: SchedulerStartPermit,
    snapshot: SchedulerRunSnapshot,
    workload: SchedulerWorkloadPlan,
) -> None:
    """Consume the one live permit immediately before fixed workflow continuation."""

    if not isinstance(permit, SchedulerStartPermit) or not isinstance(
        snapshot, SchedulerRunSnapshot
    ):
        raise SchedulerStartPermitError(
            "SCHEDULER_RUN_START_PERMIT_INVALID",
            "a live scheduler start permit and snapshot are required",
        )
    try:
        workload_binding_sha256, workload_batch_sha256 = _validated_workload_hashes(
            workload,
            snapshot,
            None,
        )
    except SchedulerRunContractError as exc:
        raise SchedulerStartPermitError(
            "SCHEDULER_RUN_START_PERMIT_INVALID",
            "the scheduler start permit workload is invalid or cross-bound",
        ) from exc
    session = permit._session
    with session.guard:
        if (
            not session.active
            or session.consumed
            or session.pid != os.getpid()
            or session.thread is not threading.current_thread()
            or snapshot._store_token is not session.store_token
            or permit.run_id != session.run_id
            or permit.identity_sha256 != session.identity_sha256
            or permit.start_intent_sha256 != session.start_intent_sha256
            or permit.workload_binding_sha256 != session.workload_binding_sha256
            or permit.workload_batch_sha256 != session.workload_batch_sha256
            or workload_binding_sha256 != session.workload_binding_sha256
            or workload_batch_sha256 != session.workload_batch_sha256
            or snapshot.run_id != session.run_id
            or snapshot.identity_sha256 != session.identity_sha256
        ):
            raise SchedulerStartPermitError(
                "SCHEDULER_RUN_START_PERMIT_INVALID",
                "the scheduler start permit is stale, consumed, or cross-bound",
            )
        session.consumed = True


def _validated_workload_hashes(
    workload: object,
    snapshot: SchedulerRunSnapshot,
    preflight: SchedulerStateSnapshot | None,
) -> tuple[str, str]:
    """Recompute one authority-sealed workload binding at the start boundary."""

    # Delayed to keep protocol-v1 and scheduler-run imports free of the dormant
    # workload module until a compute bootstrap explicitly crosses this boundary.
    from .scheduler_workload import (
        SchedulerWorkloadError,
        SchedulerWorkloadPlan,
        canonical_workload_plan_bytes,
    )

    if not isinstance(workload, SchedulerWorkloadPlan):
        raise SchedulerRunContractError("an authority-sealed scheduler workload plan is required")
    try:
        binding_sha256 = _digest(workload.binding_sha256, "workload_binding_sha256")
        batch_sha256 = _digest(workload.batch_sha256, "workload_batch_sha256")
        if (
            hashlib.sha256(canonical_workload_plan_bytes(workload)).hexdigest() != binding_sha256
            or hashlib.sha256(workload.batch_bytes).hexdigest() != batch_sha256
            or hashlib.sha256(workload.overlay_bytes).hexdigest() != workload.overlay_sha256
            or _canonical_hash(list(workload.nextflow_argv)) != workload.command_sha256
            or _canonical_hash(dict(workload.environment)) != workload.environment_sha256
        ):
            raise SchedulerRunContractError("scheduler workload plan integrity changed")
    except (SchedulerWorkloadError, TypeError, ValueError, AttributeError) as exc:
        if isinstance(exc, SchedulerRunContractError):
            raise
        raise SchedulerRunContractError("scheduler workload plan is invalid") from exc
    if (
        workload.run_id != snapshot.run_id
        or workload.run_identity_sha256 != snapshot.identity_sha256
        or workload.preflight_request_sha256 != snapshot.preflight_request_sha256
    ):
        raise SchedulerRunContractError("scheduler workload plan belongs to another run")
    if preflight is not None and (
        workload.preflight_request_sha256 != preflight.request_sha256
        or workload.preflight_revision != preflight.revision
        or workload.preflight_journal_sha256 != preflight.journal_sha256
        or workload.manifest_sha256 != preflight.state.manifest_sha256
    ):
        raise SchedulerRunContractError("scheduler workload plan belongs to another preflight")
    return binding_sha256, batch_sha256


def _open_and_close_run_lock(run: int, *, create: bool) -> None:
    descriptor = _open_lock_file(run, _RUN_LOCK, create=create)
    os.close(descriptor)


def _verify_deployment_directory_binding(
    config: TrustedSchedulerConfig,
    deployment: SchedulerDeploymentBinding,
) -> None:
    selected = PurePosixPath(deployment.deployment_dir)
    matching = [
        binding
        for binding in config.deploy_roots
        if PurePosixPath(str(binding.path)) == selected.parent
    ]
    if len(matching) != 1:
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_DEPLOYMENT_ROOT_MISMATCH",
            "scheduler deployment must be one direct child of a trusted deploy root",
        )
    root_binding = matching[0]
    root = directory = -1
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        verify_scheduler_root(config, "deploy", config.deploy_roots.index(root_binding))
        root = os.open(root_binding.path, flags)
        directory = os.open(selected.name, flags, dir_fd=root)
        opened = os.fstat(directory)
        current = os.stat(selected.name, dir_fd=root, follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_DEPLOYMENT_CHANGED",
            "scheduler deployment directory cannot be opened safely",
        ) from exc
    finally:
        if directory >= 0:
            os.close(directory)
        if root >= 0:
            os.close(root)
    identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        opened.st_gid,
        stat.S_IMODE(opened.st_mode),
    )
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_nlink < 2
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        or identity != deployment.directory_identity
    ):
        raise SchedulerRunPreconditionError(
            "SCHEDULER_RUN_DEPLOYMENT_CHANGED",
            "scheduler deployment directory identity changed",
        )


def _parse_identity(value: Mapping[str, Any]) -> None:
    expected = {
        "schema_version",
        "operation",
        "run_id",
        "preflight_id",
        "preflight_request_sha256",
        "capability_token_hash",
        "capability_issued_at",
        "capability_expires_at",
        "deployment",
        "profile_id",
        "profile_hash",
        "scheduler_policy_hash",
        "project_hash",
        "authorization_id",
        "actor",
        "approved_at",
        "key_id",
        "approval_artifact_hashes",
        "compatibility_hash",
        "request_binding_sha256",
        "consumer_binding_hash",
        "resume_run_id",
        "config_sha256",
        "contract_sha256",
    }
    if set(value) != expected or value.get("schema_version") != SCHEDULER_RUN_SCHEMA_VERSION:
        raise SchedulerRunContractError("scheduler run identity fields are invalid")
    if value["operation"] not in {"submit", "resume"}:
        raise SchedulerRunContractError("scheduler run operation is invalid")
    for field_name in ("run_id", "preflight_id", "profile_id", "authorization_id", "key_id"):
        _identifier(value[field_name], field_name)
    _actor(value["actor"])
    _approved_at(value["approved_at"])
    for field_name in (
        "preflight_request_sha256",
        "capability_token_hash",
        "profile_hash",
        "scheduler_policy_hash",
        "project_hash",
        "compatibility_hash",
        "request_binding_sha256",
        "consumer_binding_hash",
        "config_sha256",
        "contract_sha256",
    ):
        _digest(value[field_name], field_name)
    issued = _strict_int(value["capability_issued_at"], "issued_at", 0, 2**63 - 1)
    _strict_int(value["capability_expires_at"], "expires_at", issued + 1, 2**63 - 1)
    deployment = _parse_deployment(value["deployment"])
    hashes = value["approval_artifact_hashes"]
    expected_hashes = {
        "dataset_manifest",
        "pipeline_spec",
        "execution_plan",
        "software_lock",
        "execution_profile",
        "validation_report",
        "test_report",
        "preflight_report",
    }
    if not isinstance(hashes, dict) or set(hashes) != expected_hashes:
        raise SchedulerRunContractError("approval artifact hashes are invalid")
    for name, digest in hashes.items():
        if not isinstance(name, str):
            raise SchedulerRunContractError("approval artifact hash name is invalid")
        _digest(digest, name)
    expected_project = _canonical_hash(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        }
    )
    expected_compatibility = _canonical_hash(
        {
            "bundle_hash": deployment.bundle_hash,
            "execution_profile": value["profile_hash"],
            "project_hash": expected_project,
        }
    )
    if (
        hashes["execution_profile"] != value["profile_hash"]
        or expected_project != value["project_hash"]
        or expected_compatibility != value["compatibility_hash"]
    ):
        raise SchedulerRunContractError("approval hashes do not bind run identity")
    resume = value["resume_run_id"]
    if resume is not None:
        _identifier(resume, "resume_run_id")
    if (value["operation"] == "resume") != (resume is not None):
        raise SchedulerRunContractError("resume binding conflicts with operation")
    if resume == value["run_id"]:
        raise SchedulerRunContractError("resume_run_id must identify an earlier run")
    expected_consumer_binding = _canonical_hash(
        {
            "domain": "easy-pipe.scheduler-run.consumer-binding.v1",
            "operation": value["operation"],
            "run_id": value["run_id"],
            "preflight_id": value["preflight_id"],
            "preflight_request_sha256": value["preflight_request_sha256"],
            "capability_token_hash": value["capability_token_hash"],
            "capability_issued_at": value["capability_issued_at"],
            "capability_expires_at": value["capability_expires_at"],
            "deployment": value["deployment"],
            "profile_id": value["profile_id"],
            "profile_hash": value["profile_hash"],
            "scheduler_policy_hash": value["scheduler_policy_hash"],
            "project_hash": value["project_hash"],
            "bundle_hash": value["deployment"]["bundle_hash"],
            "authorization_id": value["authorization_id"],
            "actor": value["actor"],
            "approved_at": value["approved_at"],
            "key_id": value["key_id"],
            "approval_artifact_hashes": value["approval_artifact_hashes"],
            "compatibility_hash": value["compatibility_hash"],
            "request_binding_sha256": value["request_binding_sha256"],
            "resume_run_id": value["resume_run_id"],
        }
    )
    if not hmac.compare_digest(
        cast(str, value["consumer_binding_hash"]),
        expected_consumer_binding,
    ):
        raise SchedulerRunContractError("consumer binding does not match run identity")


def _parse_deployment(value: Any) -> SchedulerDeploymentBinding:
    if not isinstance(value, dict) or set(value) != {
        "deployment_id",
        "deployment_dir",
        "directory_device",
        "directory_inode",
        "directory_owner",
        "directory_group",
        "directory_mode",
        "bundle_hash",
        "files",
    }:
        raise SchedulerRunContractError("deployment binding fields are invalid")
    files_value = value["files"]
    if not isinstance(files_value, list):
        raise SchedulerRunContractError("deployment files are invalid")
    files: list[SchedulerDeploymentFile] = []
    for item in files_value:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise SchedulerRunContractError("deployment file fields are invalid")
        files.append(
            SchedulerDeploymentFile(
                path=item["path"],
                size=item["size"],
                sha256=item["sha256"],
            )
        )
    return SchedulerDeploymentBinding(
        deployment_id=value["deployment_id"],
        deployment_dir=value["deployment_dir"],
        directory_device=value["directory_device"],
        directory_inode=value["directory_inode"],
        directory_owner=value["directory_owner"],
        directory_group=value["directory_group"],
        directory_mode=value["directory_mode"],
        bundle_hash=value["bundle_hash"],
        files=tuple(files),
    )


def _canonical_record_hash(value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(
            _thaw(value),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _canonical_hash(value: Any) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SchedulerRunContractError("scheduler run binding is not canonical JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SchedulerRunContractError(f"{label} must be one safe identifier")
    return value


def _actor(value: Any) -> str:
    if not isinstance(value, str):
        raise SchedulerRunContractError("approval actor must be bounded safe text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SchedulerRunContractError("approval actor must be bounded safe text") from exc
    if (
        not value
        or len(encoded) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SchedulerRunContractError("approval actor must be bounded safe text")
    return value


def _approved_at(value: Any) -> str:
    text = _safe_text(value, "approved_at", maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchedulerRunContractError("approved_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SchedulerRunContractError("approved_at must include a timezone")
    return text


def _raw_token(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None or value == "0" * 64:
        raise SchedulerRunContractError("preflight capability token is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None or value == "0" * 64:
        raise SchedulerRunContractError(f"{label} must be a non-placeholder SHA-256")
    return value


def _strict_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SchedulerRunContractError(f"{label} is outside the supported range")
    return value


def _absolute_path(value: Any, label: str) -> str:
    text = _safe_text(value, label, maximum=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or path == PurePosixPath("/")
        or ".." in path.parts
        or str(path) != text
    ):
        raise SchedulerRunContractError(f"{label} must be a canonical non-root absolute path")
    return text


def _relative_path(value: Any) -> str:
    text = _safe_text(value, "deployment file path", maximum=4096)
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or ".." in path.parts or str(path) != text:
        raise SchedulerRunContractError("deployment file path must be canonical and relative")
    return text


def _safe_text(value: Any, label: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise SchedulerRunContractError(f"{label} must be bounded safe text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SchedulerRunContractError(f"{label} must be bounded safe text") from exc
    if (
        not value
        or len(encoded) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SchedulerRunContractError(f"{label} must be bounded safe text")
    return value


__all__ = [
    "SCHEDULER_RUN_NAMESPACE",
    "SCHEDULER_RUN_SCHEMA_VERSION",
    "SchedulerDeploymentBinding",
    "SchedulerDeploymentFile",
    "SchedulerRunBusyError",
    "SchedulerRunCommitUnknown",
    "SchedulerRunConflictError",
    "SchedulerRunContractError",
    "SchedulerRunError",
    "SchedulerRunInvalidError",
    "SchedulerRunPreconditionError",
    "SchedulerRunSnapshot",
    "SchedulerRunStore",
    "SchedulerStartPermit",
    "SchedulerStartPermitError",
    "VerifiedSchedulerRunRequest",
    "consume_start_permit",
    "verify_scheduler_run_request",
]
