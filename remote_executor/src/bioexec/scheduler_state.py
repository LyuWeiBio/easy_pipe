"""Dormant durable state and one-shot mutation permits for M7 Slurm.

The installed version-1 service does not import this module.  It owns a
separate append-only namespace beneath the trusted scheduler state root and
never starts a process itself.  A submit or release intent is created and
fsynced before a live, process- and thread-bound permit can be consumed by the
fixed scheduler runner.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import InitVar, dataclass, field, replace
from types import MappingProxyType
from typing import Any, Literal, cast

from .scheduler_config_loader import (
    SchedulerConfigLoadError,
    TrustedSchedulerConfig,
    verify_scheduler_config_file,
    verify_scheduler_root,
)
from .scheduler_preflight import (
    SchedulerPreflightError,
    SchedulerPreflightState,
    canonical_manifest_bytes,
    parse_compute_manifest,
    prepare_preflight,
    record_held_release,
    record_held_submission,
    record_release_intent,
    record_release_unknown,
    record_scheduler_poll,
    record_submit_unknown,
)
from .slurm import SlurmContractError, SlurmHeldJob, SlurmJobRef, SlurmObservation

SchedulerMutationOperation = Literal["submit_held", "release_held"]

SCHEDULER_STATE_SCHEMA_VERSION = "1.0"
_NAMESPACE = "scheduler-preflights-v1"
_CREATE_LOCK = ".create.lock"
_ATTEMPT_LOCK = "lease.lock"
_IDENTITY_FILE = "identity.json"
_REVISIONS_DIRECTORY = "revisions"
_SUBMIT_INTENT_FILE = "submit.intent.json"
_RELEASE_INTENT_FILE = "release.intent.json"
_MAX_IDENTITY_OVERHEAD_BYTES = 64 * 1024
_MAX_INTENT_BYTES = 64 * 1024
_MAX_REVISION_BYTES = 256 * 1024
_MAX_REVISIONS = 8192
_REVISION_NAME = re.compile(r"[0-9]{20}\.json", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_LOCK_FLAGS = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_CREATE_FILE_FLAGS = (
    os.O_CREAT
    | os.O_EXCL
    | os.O_WRONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)

_SNAPSHOT_AUTHORITY = object()
_PERMIT_AUTHORITY = object()

_IDENTITY_FIELDS = frozenset(
    {
        "schema_version",
        "preflight_id",
        "request_sha256",
        "config_sha256",
        "contract_sha256",
        "scheduler_policy_sha256",
        "profile_id",
        "profile_hash",
        "manifest_sha256",
        "template_sha256",
        "submission_marker",
        "manifest",
    }
)
_REVISION_FIELDS = frozenset(
    {
        "schema_version",
        "preflight_id",
        "revision",
        "previous_sha256",
        "event",
    }
)
_SUBMIT_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "preflight_id",
        "request_sha256",
        "base_revision",
        "base_journal_sha256",
        "config_sha256",
        "contract_sha256",
        "scheduler_policy_sha256",
        "manifest_sha256",
        "template_sha256",
        "submission_marker",
    }
)
_RELEASE_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "preflight_id",
        "request_sha256",
        "base_revision",
        "base_journal_sha256",
        "config_sha256",
        "contract_sha256",
        "scheduler_policy_sha256",
        "elapsed_seconds",
        "job",
        "held_state",
        "held_reason",
    }
)


class SchedulerStateError(RuntimeError):
    """Base class for sanitized durable scheduler-state failures."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


class SchedulerStateContractError(ValueError):
    """The caller supplied data outside the fixed durable state contract."""


class SchedulerStateConflictError(SchedulerStateError):
    """An immutable identity, intent, or CAS expectation conflicts."""


class SchedulerStateBusyError(SchedulerStateError):
    """Another process currently owns the nonblocking transition lease."""


class SchedulerStateInvalidError(SchedulerStateError):
    """Durable bytes or filesystem identities are incomplete or unsafe."""


class SchedulerStatePreconditionError(SchedulerStateError):
    """The trusted config or state-root identity changed."""


class SchedulerStateCommitUnknown(SchedulerStateError):
    """A create-only durable write may or may not have committed."""


class SchedulerMutationPermitError(SchedulerStateError):
    """A scheduler mutation lacks one current unconsumed durable permit."""


class SchedulerStateDeadlineError(SchedulerStateError):
    """Release authorization expired and was durably made terminal."""

    def __init__(self, snapshot: SchedulerStateSnapshot) -> None:
        self.snapshot = snapshot
        super().__init__(
            "SCHEDULER_RELEASE_DEADLINE_EXPIRED",
            "the scheduler release deadline expired before an intent was created",
        )


@dataclass(frozen=True)
class SchedulerStateSnapshot:
    """Opaque immutable view of one replayed durable attempt."""

    _authority: InitVar[object]
    state: SchedulerPreflightState
    request_sha256: str
    revision: int
    journal_sha256: str
    submit_intent_sha256: str | None
    release_intent_sha256: str | None
    _store_token: object = field(repr=False, compare=False)

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _SNAPSHOT_AUTHORITY:
            raise SchedulerStateContractError("scheduler state snapshots are store-owned")
        if not isinstance(self.state, SchedulerPreflightState):
            raise SchedulerStateContractError("scheduler state snapshot is invalid")
        _digest(self.request_sha256, "request_sha256")
        _strict_int(self.revision, "revision", 0, _MAX_REVISIONS)
        _digest(self.journal_sha256, "journal_sha256")
        for value in (self.submit_intent_sha256, self.release_intent_sha256):
            if value is not None:
                _digest(value, "intent_sha256")


@dataclass
class _LeaseSession:
    store_token: object
    config: TrustedSchedulerConfig
    config_sha256: str
    contract_sha256: str
    scheduler_policy_sha256: str
    operation: SchedulerMutationOperation
    pid: int
    thread: threading.Thread
    deadline: float
    attempt_fd: int
    revisions_fd: int
    lock_fd: int
    current: _LoadedAttempt
    intent_sha256: str
    active: bool = True
    consumed: bool = False
    guard: threading.Lock = field(default_factory=threading.Lock)


@dataclass(frozen=True)
class SchedulerMutationPermit:
    """One live lease-bound permit for exactly one scheduler mutation call."""

    _authority: InitVar[object]
    operation: SchedulerMutationOperation
    state: SchedulerPreflightState
    recovery_state: SchedulerPreflightState
    preflight_id: str
    request_sha256: str
    intent_sha256: str
    deadline: float
    _session: _LeaseSession = field(repr=False, compare=False)

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _PERMIT_AUTHORITY:
            raise SchedulerStateContractError("scheduler mutation permits are store-owned")
        if self.operation not in {"submit_held", "release_held"}:
            raise SchedulerStateContractError("scheduler mutation permit operation is invalid")
        if not isinstance(self.state, SchedulerPreflightState) or not isinstance(
            self.recovery_state, SchedulerPreflightState
        ):
            raise SchedulerStateContractError("scheduler mutation permit state is invalid")
        _identifier(self.preflight_id)
        _digest(self.request_sha256, "request_sha256")
        _digest(self.intent_sha256, "intent_sha256")
        if not math.isfinite(self.deadline):
            raise SchedulerStateContractError("scheduler mutation permit deadline is invalid")


@dataclass(frozen=True)
class _OpenAttempt:
    attempt_fd: int
    revisions_fd: int
    lock_fd: int


@dataclass(frozen=True)
class _LoadedAttempt:
    identity: Mapping[str, Any]
    identity_sha256: str
    revisions: tuple[Mapping[str, Any], ...]
    revision_hashes: tuple[str, ...]
    state: SchedulerPreflightState
    request_sha256: str
    revision: int
    journal_sha256: str
    submit_intent: Mapping[str, Any] | None
    submit_intent_sha256: str | None
    release_intent: Mapping[str, Any] | None
    release_intent_sha256: str | None


@dataclass(frozen=True)
class SchedulerPreflightStore:
    """Trusted append-only scheduler-preflight state store."""

    config: TrustedSchedulerConfig
    _store_token: object = field(default_factory=object, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.config, TrustedSchedulerConfig):
            raise SchedulerStateContractError("trusted scheduler configuration is required")

    def create_or_load(
        self,
        prepared: SchedulerPreflightState,
        *,
        request_sha256: str,
    ) -> SchedulerStateSnapshot:
        """Create one immutable attempt identity or load the exact existing one."""

        request_digest = _digest(request_sha256, "request_sha256")
        _validate_prepared(self.config, prepared)
        with self._open_namespace(create=True) as namespace:
            create_lock = _open_lock_file(namespace, _CREATE_LOCK, create=True)
            try:
                with _nonblocking_flock(create_lock, "SCHEDULER_STATE_CREATE_BUSY"):
                    _require_durable_directory(namespace)
                    try:
                        attempt = _open_private_directory(namespace, prepared.manifest.preflight_id)
                    except FileNotFoundError:
                        attempt = self._create_attempt(namespace, prepared, request_digest)
                    try:
                        opened = _open_locked_attempt(attempt)
                        try:
                            loaded = _load_attempt(
                                self.config,
                                opened,
                                prepared.manifest.preflight_id,
                            )
                        finally:
                            _close_open_attempt(opened)
                    finally:
                        os.close(attempt)
            finally:
                os.close(create_lock)
        _require_exact_identity(loaded, prepared, request_digest)
        return self._snapshot(loaded)

    def load(self, preflight_id: str, *, request_sha256: str) -> SchedulerStateSnapshot:
        """Load and replay one exact request-bound scheduler attempt."""

        selected = _identifier(preflight_id)
        request_digest = _digest(request_sha256, "request_sha256")
        with self._locked_attempt(selected) as opened:
            loaded = _load_attempt(self.config, opened, selected)
        if loaded.request_sha256 != request_digest:
            raise _conflict("SCHEDULER_REQUEST_HASH_CONFLICT")
        return self._snapshot(loaded)

    @contextlib.contextmanager
    def claim_submit(self, snapshot: SchedulerStateSnapshot) -> Iterator[SchedulerMutationPermit]:
        """Durably burn the sole submit attempt before yielding a live permit."""

        deadline = _operation_deadline(float(self.config.contract.scheduler.submit_timeout_seconds))
        selected = self._bound_snapshot(snapshot)
        with self._locked_attempt(selected.state.manifest.preflight_id) as opened:
            loaded = _load_attempt(self.config, opened, selected.state.manifest.preflight_id)
            _require_snapshot_cas(loaded, selected)
            if loaded.state.phase != "prepared" or loaded.submit_intent is not None:
                raise _conflict("SCHEDULER_SUBMIT_ALREADY_CLAIMED")
            _require_live_deadline(deadline)
            intent = _submit_intent_mapping(self.config, loaded)
            intent_sha256 = _create_record(
                opened.attempt_fd,
                _SUBMIT_INTENT_FILE,
                intent,
                _MAX_INTENT_BYTES,
            )
            recovery = record_submit_unknown(loaded.state)
            session = _LeaseSession(
                store_token=self._store_token,
                config=self.config,
                config_sha256=self.config.config_sha256,
                contract_sha256=self.config.contract_sha256,
                scheduler_policy_sha256=self.config.scheduler_policy_hash,
                operation="submit_held",
                pid=os.getpid(),
                thread=threading.current_thread(),
                deadline=deadline,
                attempt_fd=opened.attempt_fd,
                revisions_fd=opened.revisions_fd,
                lock_fd=opened.lock_fd,
                current=_with_submit_intent(loaded, intent, intent_sha256, recovery),
                intent_sha256=intent_sha256,
            )
            permit = SchedulerMutationPermit(
                _authority=_PERMIT_AUTHORITY,
                operation="submit_held",
                state=loaded.state,
                recovery_state=recovery,
                preflight_id=loaded.state.manifest.preflight_id,
                request_sha256=loaded.request_sha256,
                intent_sha256=intent_sha256,
                deadline=deadline,
                _session=session,
            )
            try:
                yield permit
            finally:
                session.active = False

    @contextlib.contextmanager
    def claim_release(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        elapsed_seconds: int,
    ) -> Iterator[SchedulerMutationPermit]:
        """Durably burn the sole exact held-job release before yielding a permit."""

        deadline = _operation_deadline(self.config.contract.limits.command_timeout_seconds)
        selected = self._bound_snapshot(snapshot)
        with self._locked_attempt(selected.state.manifest.preflight_id) as opened:
            loaded = _load_attempt(self.config, opened, selected.state.manifest.preflight_id)
            _require_snapshot_cas(loaded, selected)
            if loaded.state.phase != "held" or loaded.release_intent is not None:
                raise _conflict("SCHEDULER_RELEASE_ALREADY_CLAIMED")
            try:
                ready = record_release_intent(loaded.state, elapsed_seconds=elapsed_seconds)
            except SchedulerPreflightError as exc:
                raise SchedulerStateContractError("release elapsed time is invalid") from exc
            if ready.phase == "timed_out":
                event = {
                    "type": "release_timed_out",
                    "elapsed_seconds": ready.elapsed_seconds,
                }
                current = _append_revision(self.config, opened, loaded, event)
                raise SchedulerStateDeadlineError(self._snapshot(current))
            if ready.phase != "release_ready":
                raise SchedulerStateContractError("release intent did not produce release_ready")
            _require_live_deadline(deadline)
            intent = _release_intent_mapping(self.config, loaded, ready)
            intent_sha256 = _create_record(
                opened.attempt_fd,
                _RELEASE_INTENT_FILE,
                intent,
                _MAX_INTENT_BYTES,
            )
            recovery = record_release_unknown(ready)
            session = _LeaseSession(
                store_token=self._store_token,
                config=self.config,
                config_sha256=self.config.config_sha256,
                contract_sha256=self.config.contract_sha256,
                scheduler_policy_sha256=self.config.scheduler_policy_hash,
                operation="release_held",
                pid=os.getpid(),
                thread=threading.current_thread(),
                deadline=deadline,
                attempt_fd=opened.attempt_fd,
                revisions_fd=opened.revisions_fd,
                lock_fd=opened.lock_fd,
                current=_with_release_intent(loaded, intent, intent_sha256, recovery),
                intent_sha256=intent_sha256,
            )
            permit = SchedulerMutationPermit(
                _authority=_PERMIT_AUTHORITY,
                operation="release_held",
                state=ready,
                recovery_state=recovery,
                preflight_id=loaded.state.manifest.preflight_id,
                request_sha256=loaded.request_sha256,
                intent_sha256=intent_sha256,
                deadline=deadline,
                _session=session,
            )
            try:
                yield permit
            finally:
                session.active = False

    def record_held(
        self,
        permit: SchedulerMutationPermit,
        held_job: SlurmHeldJob,
        *,
        invocation_sha256: str | None = None,
    ) -> SchedulerStateSnapshot:
        """Bind exact held evidence while the original submit lease is live."""

        session = self._active_session(permit, "submit_held", require_consumed=True)
        loaded = session.current
        held = _validated_held(held_job)
        invocation_digest = _optional_digest(invocation_sha256)
        if loaded.state.phase == "held":
            event = cast(Mapping[str, Any], loaded.revisions[-1]["event"])
            if (
                loaded.state.held_job == held
                and event.get("type") == "held_bound"
                and event.get("invocation_sha256") == invocation_digest
            ):
                return self._snapshot(loaded)
            raise _conflict("SCHEDULER_HELD_EVIDENCE_CONFLICT")
        _require_phase(loaded.state, "submit_unknown")
        _validate_held_transition(loaded.state, held)
        event = {
            "type": "held_bound",
            "submit_intent_sha256": permit.intent_sha256,
            "held_job": _held_mapping(held),
            "invocation_sha256": invocation_digest,
        }
        current = _append_revision(
            self.config,
            _OpenAttempt(session.attempt_fd, session.revisions_fd, session.lock_fd),
            loaded,
            event,
        )
        session.current = current
        return self._snapshot(current)

    def record_recovered_held(
        self,
        snapshot: SchedulerStateSnapshot,
        held_job: SlurmHeldJob,
    ) -> SchedulerStateSnapshot:
        """Resolve a burned submit only from exact positive held-job evidence."""

        held = _validated_held(held_job)
        selected = self._bound_snapshot(snapshot)
        with self._locked_attempt(selected.state.manifest.preflight_id) as opened:
            loaded = _load_attempt(self.config, opened, selected.state.manifest.preflight_id)
            if loaded.state.phase == "held" and loaded.state.held_job == held:
                return self._snapshot(loaded)
            _require_snapshot_cas(loaded, selected)
            _require_phase(loaded.state, "submit_unknown")
            if loaded.submit_intent_sha256 is None:
                raise _invalid("SCHEDULER_SUBMIT_INTENT_MISSING")
            _validate_held_transition(loaded.state, held)
            event = {
                "type": "held_bound",
                "submit_intent_sha256": loaded.submit_intent_sha256,
                "held_job": _held_mapping(held),
                "invocation_sha256": None,
            }
            current = _append_revision(self.config, opened, loaded, event)
        return self._snapshot(current)

    def record_release_success(
        self,
        permit: SchedulerMutationPermit,
        *,
        invocation_sha256: str,
    ) -> SchedulerStateSnapshot:
        """Append release success only for the consumed live release permit."""

        session = self._active_session(permit, "release_held", require_consumed=True)
        digest = _digest(invocation_sha256, "invocation_sha256")
        loaded = session.current
        if loaded.state.phase == "polling":
            event = cast(Mapping[str, Any], loaded.revisions[-1]["event"])
            if (
                event.get("type") == "release_succeeded"
                and event.get("invocation_sha256") == digest
            ):
                return self._snapshot(loaded)
            raise _conflict("SCHEDULER_RELEASE_EVIDENCE_CONFLICT")
        _require_phase(loaded.state, "release_unknown")
        event = {
            "type": "release_succeeded",
            "release_intent_sha256": permit.intent_sha256,
            "invocation_sha256": digest,
        }
        current = _append_revision(
            self.config,
            _OpenAttempt(session.attempt_fd, session.revisions_fd, session.lock_fd),
            loaded,
            event,
        )
        session.current = current
        return self._snapshot(current)

    def record_scheduler_poll(
        self,
        snapshot: SchedulerStateSnapshot,
        *,
        queue: SlurmObservation | None,
        accounting: SlurmObservation | None,
        elapsed_seconds: int,
    ) -> SchedulerStateSnapshot:
        """Append one read-only recovery or lifecycle observation transition."""

        selected = self._bound_snapshot(snapshot)
        with self._locked_attempt(selected.state.manifest.preflight_id) as opened:
            loaded = _load_attempt(self.config, opened, selected.state.manifest.preflight_id)
            _require_snapshot_cas(loaded, selected)
            if loaded.state.phase not in {"release_unknown", "polling"}:
                raise _conflict("SCHEDULER_POLL_PHASE_CONFLICT")
            if loaded.release_intent_sha256 is None:
                raise _invalid("SCHEDULER_RELEASE_INTENT_MISSING")
            try:
                record_scheduler_poll(
                    loaded.state,
                    queue=queue,
                    accounting=accounting,
                    elapsed_seconds=elapsed_seconds,
                )
            except SchedulerPreflightError as exc:
                raise SchedulerStateContractError("scheduler poll evidence is invalid") from exc
            event = {
                "type": "scheduler_poll",
                "release_intent_sha256": loaded.release_intent_sha256,
                "queue": _observation_mapping(queue),
                "accounting": _observation_mapping(accounting),
                "elapsed_seconds": elapsed_seconds,
            }
            current = _append_revision(self.config, opened, loaded, event)
        return self._snapshot(current)

    def _active_session(
        self,
        permit: SchedulerMutationPermit,
        operation: SchedulerMutationOperation,
        *,
        require_consumed: bool,
    ) -> _LeaseSession:
        if not isinstance(permit, SchedulerMutationPermit):
            raise SchedulerMutationPermitError(
                "SCHEDULER_MUTATION_PERMIT_REQUIRED",
                "a live durable scheduler mutation permit is required",
            )
        session = permit._session
        if (
            session.store_token is not self._store_token
            or not session.active
            or session.operation != operation
            or session.pid != os.getpid()
            or session.thread is not threading.current_thread()
            or (require_consumed and not session.consumed)
        ):
            raise SchedulerMutationPermitError(
                "SCHEDULER_MUTATION_PERMIT_INVALID",
                "the durable scheduler mutation permit is no longer valid",
            )
        return session

    def _bound_snapshot(self, snapshot: SchedulerStateSnapshot) -> SchedulerStateSnapshot:
        if not isinstance(snapshot, SchedulerStateSnapshot) or (
            snapshot._store_token is not self._store_token
        ):
            raise SchedulerStateContractError("snapshot does not belong to this store instance")
        return snapshot

    def _snapshot(self, loaded: _LoadedAttempt) -> SchedulerStateSnapshot:
        return SchedulerStateSnapshot(
            _authority=_SNAPSHOT_AUTHORITY,
            state=loaded.state,
            request_sha256=loaded.request_sha256,
            revision=loaded.revision,
            journal_sha256=loaded.journal_sha256,
            submit_intent_sha256=loaded.submit_intent_sha256,
            release_intent_sha256=loaded.release_intent_sha256,
            _store_token=self._store_token,
        )

    @contextlib.contextmanager
    def _open_namespace(self, *, create: bool) -> Iterator[int]:
        root = _open_state_root(self.config)
        namespace = -1
        try:
            if create:
                try:
                    os.mkdir(_NAMESPACE, 0o700, dir_fd=root)
                    namespace = os.open(_NAMESPACE, _DIRECTORY_FLAGS, dir_fd=root)
                    os.fchmod(namespace, 0o700)
                except FileExistsError:
                    pass
            if namespace < 0:
                try:
                    namespace = _open_private_directory(root, _NAMESPACE)
                except FileNotFoundError as exc:
                    raise SchedulerStateError(
                        "SCHEDULER_STATE_NOT_FOUND",
                        "the scheduler-preflight state namespace does not exist",
                    ) from exc
            _verify_private_directory(namespace, root, _NAMESPACE)
            # Adopt entries left by a process that stopped before syncing
            # either parent.  No permit may outlive an undurable ancestor.
            _require_durable_directory(namespace)
            _require_durable_directory(root)
            yield namespace
        finally:
            if namespace >= 0:
                os.close(namespace)
            os.close(root)

    def _create_attempt(
        self,
        namespace: int,
        prepared: SchedulerPreflightState,
        request_sha256: str,
    ) -> int:
        preflight_id = prepared.manifest.preflight_id
        try:
            os.mkdir(preflight_id, 0o700, dir_fd=namespace)
        except FileExistsError as exc:
            raise _conflict("SCHEDULER_ATTEMPT_ALREADY_EXISTS") from exc
        attempt = _open_created_private_directory(namespace, preflight_id)
        try:
            os.mkdir(_REVISIONS_DIRECTORY, 0o700, dir_fd=attempt)
            revisions = _open_created_private_directory(attempt, _REVISIONS_DIRECTORY)
            try:
                os.fsync(revisions)
            finally:
                os.close(revisions)
            lock = os.open(_ATTEMPT_LOCK, _CREATE_FILE_FLAGS, 0o600, dir_fd=attempt)
            try:
                os.fchmod(lock, 0o600)
                os.fsync(lock)
            finally:
                os.close(lock)
            identity = _identity_mapping(self.config, prepared, request_sha256)
            maximum = self.config.contract.limits.max_request_bytes + (_MAX_IDENTITY_OVERHEAD_BYTES)
            _create_record(attempt, _IDENTITY_FILE, identity, maximum, fsync_parent=False)
            os.fsync(attempt)
            os.fsync(namespace)
            return attempt
        except BaseException:
            os.close(attempt)
            raise

    @contextlib.contextmanager
    def _locked_attempt(self, preflight_id: str) -> Iterator[_OpenAttempt]:
        selected = _identifier(preflight_id)
        with self._open_namespace(create=False) as namespace:
            try:
                create_lock = _open_lock_file(namespace, _CREATE_LOCK, create=False)
            except FileNotFoundError as exc:
                raise _invalid("SCHEDULER_CREATE_LOCK_MISSING") from exc
            try:
                with _nonblocking_flock(create_lock, "SCHEDULER_STATE_CREATE_BUSY"):
                    _require_durable_directory(namespace)
                    try:
                        attempt = _open_private_directory(namespace, selected)
                    except FileNotFoundError as exc:
                        raise SchedulerStateError(
                            "SCHEDULER_STATE_NOT_FOUND",
                            "the scheduler-preflight attempt does not exist",
                        ) from exc
                    try:
                        opened = _open_locked_attempt(attempt)
                    finally:
                        os.close(attempt)
            finally:
                os.close(create_lock)
        try:
            yield opened
        finally:
            _close_open_attempt(opened)


def _consume_mutation_permit(
    permit: SchedulerMutationPermit,
    operation: SchedulerMutationOperation,
    state: SchedulerPreflightState,
    config: TrustedSchedulerConfig,
) -> float:
    """Consume and return the live absolute deadline for the fixed runner."""

    if not isinstance(permit, SchedulerMutationPermit):
        raise SchedulerMutationPermitError(
            "SCHEDULER_MUTATION_PERMIT_REQUIRED",
            "a live durable scheduler mutation permit is required",
        )
    session = permit._session
    if not isinstance(config, TrustedSchedulerConfig) or (
        operation not in {"submit_held", "release_held"}
    ):
        raise SchedulerMutationPermitError(
            "SCHEDULER_MUTATION_PERMIT_INVALID",
            "the scheduler mutation permit binding is invalid",
        )
    with session.guard:
        valid = (
            session.active
            and not session.consumed
            and session.operation == operation
            and permit.operation == operation
            and permit.state is state
            and session.pid == os.getpid()
            and session.thread is threading.current_thread()
            and session.config is config
            and session.config_sha256 == config.config_sha256
            and session.contract_sha256 == config.contract_sha256
            and session.scheduler_policy_sha256 == config.scheduler_policy_hash
            and permit.intent_sha256 == session.intent_sha256
            and permit.deadline == session.deadline
            and time.monotonic() < session.deadline
        )
        if not valid:
            raise SchedulerMutationPermitError(
                "SCHEDULER_MUTATION_PERMIT_INVALID",
                "the scheduler mutation permit is expired, stale, or already consumed",
            )
        session.consumed = True
    return session.deadline


def _require_durable_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise SchedulerStatePreconditionError(
            "SCHEDULER_STATE_DIRECTORY_SYNC_FAILED",
            "the scheduler state namespace cannot be made durable",
        ) from exc


def _open_state_root(config: TrustedSchedulerConfig) -> int:
    if os.name != "posix":
        raise SchedulerStatePreconditionError(
            "SCHEDULER_STATE_POSIX_REQUIRED",
            "durable scheduler state requires POSIX filesystem semantics",
        )
    descriptor = -1
    try:
        verify_scheduler_config_file(config)
        verify_scheduler_root(config, "state")
        descriptor = os.open(config.state_root.path, _DIRECTORY_FLAGS)
        metadata = os.fstat(descriptor)
    except SchedulerConfigLoadError as exc:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise SchedulerStatePreconditionError(
            "SCHEDULER_TRUSTED_STATE_ROOT_CHANGED",
            "the trusted scheduler state root changed",
        ) from exc
    except OSError as exc:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise SchedulerStatePreconditionError(
            "SCHEDULER_TRUSTED_STATE_ROOT_UNAVAILABLE",
            "the trusted scheduler state root is unavailable",
        ) from exc
    expected = config.state_root
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != (expected.device, expected.inode)
        or metadata.st_uid != expected.owner
        or metadata.st_gid != expected.group
        or stat.S_IMODE(metadata.st_mode) != expected.mode
    ):
        os.close(descriptor)
        raise SchedulerStatePreconditionError(
            "SCHEDULER_TRUSTED_STATE_ROOT_CHANGED",
            "the trusted scheduler state root changed",
        )
    return descriptor


def _open_private_directory(parent: int, name: str) -> int:
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        _verify_private_directory(descriptor, parent, name)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_created_private_directory(parent: int, name: str) -> int:
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        os.fchmod(descriptor, 0o700)
        _verify_private_directory(descriptor, parent, name)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_private_directory(descriptor: int, parent: int, name: str) -> None:
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        raise _invalid("SCHEDULER_STATE_DIRECTORY_INVALID") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_nlink < 2
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise _invalid("SCHEDULER_STATE_DIRECTORY_INVALID")


def _open_lock_file(directory: int, name: str, *, create: bool) -> int:
    created = False
    if create:
        try:
            descriptor = os.open(
                name,
                _LOCK_FLAGS | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(name, _LOCK_FLAGS, dir_fd=directory)
    else:
        descriptor = os.open(name, _LOCK_FLAGS, dir_fd=directory)
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        _verify_private_file(
            descriptor,
            directory,
            name,
            allow_empty=True,
            maximum_bytes=0,
        )
        if created:
            os.fsync(descriptor)
            os.fsync(directory)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def _nonblocking_flock(descriptor: int, reason_code: str) -> Iterator[None]:
    try:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SchedulerStateBusyError(
            reason_code,
            "another scheduler state transition currently owns the lease",
        ) from exc
    except (ImportError, OSError) as exc:
        raise SchedulerStatePreconditionError(
            "SCHEDULER_STATE_LOCK_UNAVAILABLE",
            "the scheduler state lease cannot be acquired safely",
        ) from exc
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)


def _open_locked_attempt(attempt: int) -> _OpenAttempt:
    duplicated = os.dup(attempt)
    revisions = -1
    lock = -1
    try:
        revisions = _open_private_directory(duplicated, _REVISIONS_DIRECTORY)
        lock = _open_lock_file(duplicated, _ATTEMPT_LOCK, create=False)
        try:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SchedulerStateBusyError(
                "SCHEDULER_ATTEMPT_BUSY",
                "another scheduler transition owns this attempt lease",
            ) from exc
        except (ImportError, OSError) as exc:
            raise SchedulerStatePreconditionError(
                "SCHEDULER_STATE_LOCK_UNAVAILABLE",
                "the scheduler attempt lease cannot be acquired safely",
            ) from exc
        _require_durable_directory(revisions)
        _require_durable_directory(duplicated)
        return _OpenAttempt(duplicated, revisions, lock)
    except BaseException:
        if lock >= 0:
            os.close(lock)
        if revisions >= 0:
            os.close(revisions)
        os.close(duplicated)
        raise


def _close_open_attempt(opened: _OpenAttempt) -> None:
    for descriptor in (opened.lock_fd, opened.revisions_fd, opened.attempt_fd):
        with contextlib.suppress(BaseException):
            os.close(descriptor)


def _verify_private_file(
    descriptor: int,
    directory: int,
    name: str,
    *,
    allow_empty: bool,
    maximum_bytes: int | None = None,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise _invalid("SCHEDULER_STATE_FILE_INVALID") from exc
    invalid_size = opened.st_size < 0 if allow_empty else opened.st_size <= 0
    if maximum_bytes is not None and opened.st_size > maximum_bytes:
        invalid_size = True
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or invalid_size
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise _invalid("SCHEDULER_STATE_FILE_INVALID")
    return opened


def _create_record(
    directory: int,
    name: str,
    value: Mapping[str, Any],
    maximum_bytes: int,
    *,
    fsync_parent: bool = True,
) -> str:
    data = _canonical_json_bytes(value)
    if not 0 < len(data) <= maximum_bytes:
        raise SchedulerStateContractError("durable scheduler record exceeds its byte budget")
    try:
        descriptor = os.open(name, _CREATE_FILE_FLAGS, 0o600, dir_fd=directory)
    except FileExistsError as exc:
        raise _conflict("SCHEDULER_CREATE_ONLY_RECORD_EXISTS") from exc
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise SchedulerStateCommitUnknown(
            "SCHEDULER_CREATE_ONLY_COMMIT_UNKNOWN",
            "a create-only scheduler record may be incomplete",
        ) from exc
    try:
        os.close(descriptor)
    except BaseException as exc:
        # A failed close is not retried: the descriptor state is unspecified,
        # while the create-only record may already be durable.
        raise SchedulerStateCommitUnknown(
            "SCHEDULER_CREATE_ONLY_COMMIT_UNKNOWN",
            "a create-only scheduler record may be incomplete",
        ) from exc
    try:
        if fsync_parent:
            os.fsync(directory)
    except OSError as exc:
        raise SchedulerStateCommitUnknown(
            "SCHEDULER_DIRECTORY_COMMIT_UNKNOWN",
            "a scheduler record directory entry may not be durable",
        ) from exc
    return hashlib.sha256(data).hexdigest()


def _read_record(
    directory: int,
    name: str,
    maximum_bytes: int,
) -> tuple[dict[str, Any], str]:
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _invalid("SCHEDULER_STATE_FILE_INVALID") from exc
    try:
        before = _verify_private_file(
            descriptor,
            directory,
            name,
            allow_empty=False,
            maximum_bytes=maximum_bytes,
        )
        raw = _read_bounded(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) > maximum_bytes or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise _invalid("SCHEDULER_STATE_FILE_CHANGED")
    value = _decode_canonical_object(raw)
    return value, hashlib.sha256(raw).hexdigest()


def _read_optional_record(
    directory: int,
    name: str,
    maximum_bytes: int,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        raise _invalid("SCHEDULER_INTENT_STATE_UNKNOWN") from exc
    try:
        return _read_record(directory, name, maximum_bytes)
    except FileNotFoundError as exc:
        # Existence was observed.  Disappearance is not permission to replay.
        raise _invalid("SCHEDULER_INTENT_STATE_UNKNOWN") from exc


def _load_attempt(
    config: TrustedSchedulerConfig,
    opened: _OpenAttempt,
    preflight_id: str,
) -> _LoadedAttempt:
    maximum_identity = config.contract.limits.max_request_bytes + _MAX_IDENTITY_OVERHEAD_BYTES
    identity, identity_sha256 = _read_record(
        opened.attempt_fd,
        _IDENTITY_FILE,
        maximum_identity,
    )
    _exact_fields(identity, _IDENTITY_FIELDS, "scheduler identity")
    _validate_identity(config, identity, preflight_id)

    names: list[str] = []
    try:
        with os.scandir(opened.revisions_fd) as entries:
            for entry in entries:
                if len(names) >= _MAX_REVISIONS or not _REVISION_NAME.fullmatch(entry.name):
                    raise _invalid("SCHEDULER_REVISION_SET_INVALID")
                names.append(entry.name)
    except SchedulerStateInvalidError:
        raise
    except OSError as exc:
        raise _invalid("SCHEDULER_REVISION_DIRECTORY_INVALID") from exc
    ordered = sorted(names)
    expected_names = [f"{revision:020d}.json" for revision in range(1, len(ordered) + 1)]
    if ordered != expected_names:
        raise _invalid("SCHEDULER_REVISION_SET_INVALID")

    revisions: list[Mapping[str, Any]] = []
    hashes: list[str] = [identity_sha256]
    previous = identity_sha256
    for number, name in enumerate(ordered, start=1):
        revision, revision_sha256 = _read_record(
            opened.revisions_fd,
            name,
            _MAX_REVISION_BYTES,
        )
        _exact_fields(revision, _REVISION_FIELDS, "scheduler revision")
        if (
            revision["schema_version"] != SCHEDULER_STATE_SCHEMA_VERSION
            or revision["preflight_id"] != preflight_id
            or type(revision["revision"]) is not int
            or revision["revision"] != number
            or revision["previous_sha256"] != previous
        ):
            raise _invalid("SCHEDULER_REVISION_CHAIN_INVALID")
        if not isinstance(revision["event"], dict):
            raise _invalid("SCHEDULER_REVISION_EVENT_INVALID")
        revisions.append(MappingProxyType(revision))
        hashes.append(revision_sha256)
        previous = revision_sha256

    submit_intent, submit_sha256 = _read_optional_record(
        opened.attempt_fd,
        _SUBMIT_INTENT_FILE,
        _MAX_INTENT_BYTES,
    )
    release_intent, release_sha256 = _read_optional_record(
        opened.attempt_fd,
        _RELEASE_INTENT_FILE,
        _MAX_INTENT_BYTES,
    )
    if submit_intent is not None:
        _exact_fields(submit_intent, _SUBMIT_INTENT_FIELDS, "submit intent")
        _validate_intent_base(submit_intent, identity, hashes, "submit_held")
    if release_intent is not None:
        _exact_fields(release_intent, _RELEASE_INTENT_FIELDS, "release intent")
        _validate_intent_base(release_intent, identity, hashes, "release_held")

    state = _replay(
        identity,
        tuple(revisions),
        submit_intent,
        submit_sha256,
        release_intent,
        release_sha256,
    )
    return _LoadedAttempt(
        identity=MappingProxyType(identity),
        identity_sha256=identity_sha256,
        revisions=tuple(revisions),
        revision_hashes=tuple(hashes),
        state=state,
        request_sha256=cast(str, identity["request_sha256"]),
        revision=len(revisions),
        journal_sha256=previous,
        submit_intent=(MappingProxyType(submit_intent) if submit_intent is not None else None),
        submit_intent_sha256=submit_sha256,
        release_intent=(MappingProxyType(release_intent) if release_intent is not None else None),
        release_intent_sha256=release_sha256,
    )


def _replay(
    identity: Mapping[str, Any],
    revisions: tuple[Mapping[str, Any], ...],
    submit_intent: Mapping[str, Any] | None,
    submit_intent_sha256: str | None,
    release_intent: Mapping[str, Any] | None,
    release_intent_sha256: str | None,
) -> SchedulerPreflightState:
    try:
        manifest = parse_compute_manifest(identity["manifest"])
        state = prepare_preflight(manifest)
        if submit_intent is not None:
            _validate_submit_intent_state(submit_intent, state)
            state = record_submit_unknown(state)
        release_ready: SchedulerPreflightState | None = None
        release_base_revision = (
            cast(int, release_intent["base_revision"]) if release_intent is not None else None
        )
        if release_base_revision == 0:
            raise SchedulerPreflightError("release intent cannot precede held evidence")

        for revision in revisions:
            number = cast(int, revision["revision"])
            event = cast(dict[str, Any], revision["event"])
            event_type = event.get("type")
            if event_type == "held_bound":
                _exact_fields(
                    event,
                    {
                        "type",
                        "submit_intent_sha256",
                        "held_job",
                        "invocation_sha256",
                    },
                    "held revision",
                )
                if (
                    submit_intent_sha256 is None
                    or event["submit_intent_sha256"] != submit_intent_sha256
                ):
                    raise SchedulerPreflightError("held evidence lacks the exact submit intent")
                _optional_digest(event["invocation_sha256"])
                state = record_held_submission(state, _parse_held(event["held_job"]))
            elif event_type == "release_succeeded":
                _exact_fields(
                    event,
                    {"type", "release_intent_sha256", "invocation_sha256"},
                    "release success revision",
                )
                if (
                    release_ready is None
                    or release_intent_sha256 is None
                    or event["release_intent_sha256"] != release_intent_sha256
                ):
                    raise SchedulerPreflightError("release success lacks the exact intent")
                _digest(event["invocation_sha256"], "invocation_sha256")
                if state.phase != "release_unknown":
                    raise SchedulerPreflightError("release success revision is out of order")
                state = record_held_release(release_ready)
                release_ready = None
            elif event_type == "scheduler_poll":
                _exact_fields(
                    event,
                    {
                        "type",
                        "release_intent_sha256",
                        "queue",
                        "accounting",
                        "elapsed_seconds",
                    },
                    "scheduler poll revision",
                )
                if (
                    release_intent_sha256 is None
                    or event["release_intent_sha256"] != release_intent_sha256
                    or state.phase not in {"release_unknown", "polling"}
                ):
                    raise SchedulerPreflightError("scheduler poll revision is out of order")
                state = record_scheduler_poll(
                    state,
                    queue=_parse_observation(event["queue"]),
                    accounting=_parse_observation(event["accounting"]),
                    elapsed_seconds=_strict_int(
                        event["elapsed_seconds"],
                        "elapsed_seconds",
                        0,
                        2**63 - 1,
                    ),
                )
                release_ready = None
            elif event_type == "release_timed_out":
                _exact_fields(
                    event,
                    {"type", "elapsed_seconds"},
                    "release timeout revision",
                )
                if release_intent is not None or state.phase != "held":
                    raise SchedulerPreflightError("release timeout revision is out of order")
                state = record_release_intent(
                    state,
                    elapsed_seconds=_strict_int(
                        event["elapsed_seconds"],
                        "elapsed_seconds",
                        0,
                        2**63 - 1,
                    ),
                )
                if state.phase != "timed_out":
                    raise SchedulerPreflightError("release timeout revision is not terminal")
            else:
                raise SchedulerPreflightError("scheduler revision event type is unsupported")

            if release_intent is not None and release_base_revision == number:
                if state.phase != "held":
                    raise SchedulerPreflightError("release intent base is not held state")
                _validate_release_intent_state(release_intent, state)
                release_ready = record_release_intent(
                    state,
                    elapsed_seconds=cast(int, release_intent["elapsed_seconds"]),
                )
                if release_ready.phase != "release_ready":
                    raise SchedulerPreflightError("persisted release intent is not fresh")
                state = record_release_unknown(release_ready)

        if release_intent is not None and release_base_revision == len(revisions):
            # The overlay was applied in-loop when the base was a non-zero
            # revision.  This branch only documents the required end state.
            if state.phase not in {
                "release_unknown",
                "polling",
                "awaiting_evidence",
                "failed",
                "indeterminate",
                "timed_out",
            }:
                raise SchedulerPreflightError("release intent did not produce recovery state")
        elif (
            release_intent is not None
            and release_base_revision is not None
            and (release_base_revision > len(revisions))
        ):
            raise SchedulerPreflightError("release intent base revision is unavailable")
    except (SchedulerPreflightError, SlurmContractError, KeyError, TypeError, ValueError) as exc:
        raise _invalid("SCHEDULER_STATE_REPLAY_INVALID") from exc
    return state


def _append_revision(
    config: TrustedSchedulerConfig,
    opened: _OpenAttempt,
    loaded: _LoadedAttempt,
    event: Mapping[str, Any],
) -> _LoadedAttempt:
    revision_number = loaded.revision + 1
    if revision_number > _MAX_REVISIONS:
        raise SchedulerStateError(
            "SCHEDULER_REVISION_LIMIT_REACHED",
            "the scheduler state revision limit was reached",
        )
    revision = {
        "schema_version": SCHEDULER_STATE_SCHEMA_VERSION,
        "preflight_id": loaded.state.manifest.preflight_id,
        "revision": revision_number,
        "previous_sha256": loaded.journal_sha256,
        "event": dict(event),
    }
    name = f"{revision_number:020d}.json"
    _create_record(
        opened.revisions_fd,
        name,
        revision,
        _MAX_REVISION_BYTES,
    )
    try:
        return _load_attempt(config, opened, loaded.state.manifest.preflight_id)
    except BaseException as exc:
        raise SchedulerStateCommitUnknown(
            "SCHEDULER_REVISION_POST_COMMIT_UNKNOWN",
            "a durable scheduler revision could not be reloaded safely",
        ) from exc


def _identity_mapping(
    config: TrustedSchedulerConfig,
    prepared: SchedulerPreflightState,
    request_sha256: str,
) -> dict[str, Any]:
    manifest_bytes = canonical_manifest_bytes(prepared.manifest)
    if len(manifest_bytes) > config.contract.limits.max_request_bytes:
        raise SchedulerStateContractError("compute manifest exceeds max_request_bytes")
    return {
        "schema_version": SCHEDULER_STATE_SCHEMA_VERSION,
        "preflight_id": prepared.manifest.preflight_id,
        "request_sha256": request_sha256,
        "config_sha256": config.config_sha256,
        "contract_sha256": config.contract_sha256,
        "scheduler_policy_sha256": config.scheduler_policy_hash,
        "profile_id": config.contract.profile_id,
        "profile_hash": config.contract.profile_hash,
        "manifest_sha256": prepared.manifest_sha256,
        "template_sha256": prepared.template_sha256,
        "submission_marker": prepared.submission_marker,
        "manifest": prepared.manifest.as_mapping(),
    }


def _submit_intent_mapping(
    config: TrustedSchedulerConfig,
    loaded: _LoadedAttempt,
) -> dict[str, Any]:
    state = loaded.state
    return {
        "schema_version": SCHEDULER_STATE_SCHEMA_VERSION,
        "operation": "submit_held",
        "preflight_id": state.manifest.preflight_id,
        "request_sha256": loaded.request_sha256,
        "base_revision": loaded.revision,
        "base_journal_sha256": loaded.journal_sha256,
        "config_sha256": config.config_sha256,
        "contract_sha256": config.contract_sha256,
        "scheduler_policy_sha256": config.scheduler_policy_hash,
        "manifest_sha256": state.manifest_sha256,
        "template_sha256": state.template_sha256,
        "submission_marker": state.submission_marker,
    }


def _release_intent_mapping(
    config: TrustedSchedulerConfig,
    loaded: _LoadedAttempt,
    ready: SchedulerPreflightState,
) -> dict[str, Any]:
    if ready.held_job is None:
        raise SchedulerStateContractError("release intent lacks exact held evidence")
    return {
        "schema_version": SCHEDULER_STATE_SCHEMA_VERSION,
        "operation": "release_held",
        "preflight_id": ready.manifest.preflight_id,
        "request_sha256": loaded.request_sha256,
        "base_revision": loaded.revision,
        "base_journal_sha256": loaded.journal_sha256,
        "config_sha256": config.config_sha256,
        "contract_sha256": config.contract_sha256,
        "scheduler_policy_sha256": config.scheduler_policy_hash,
        "elapsed_seconds": ready.elapsed_seconds,
        "job": _job_mapping(ready.held_job.job),
        "held_state": ready.held_job.state,
        "held_reason": ready.held_job.reason,
    }


def _with_submit_intent(
    loaded: _LoadedAttempt,
    intent: Mapping[str, Any],
    intent_sha256: str,
    recovery: SchedulerPreflightState,
) -> _LoadedAttempt:
    return replace(
        loaded,
        state=recovery,
        submit_intent=MappingProxyType(dict(intent)),
        submit_intent_sha256=intent_sha256,
    )


def _with_release_intent(
    loaded: _LoadedAttempt,
    intent: Mapping[str, Any],
    intent_sha256: str,
    recovery: SchedulerPreflightState,
) -> _LoadedAttempt:
    return replace(
        loaded,
        state=recovery,
        release_intent=MappingProxyType(dict(intent)),
        release_intent_sha256=intent_sha256,
    )


def _validate_prepared(
    config: TrustedSchedulerConfig,
    state: SchedulerPreflightState,
) -> None:
    if not isinstance(state, SchedulerPreflightState) or state.phase != "prepared":
        raise SchedulerStateContractError("initial scheduler state must be prepared")
    try:
        rebuilt = prepare_preflight(state.manifest)
    except SchedulerPreflightError as exc:
        raise SchedulerStateContractError("compute preflight manifest is invalid") from exc
    if (
        rebuilt != state
        or state.manifest.profile_id != config.contract.profile_id
        or state.manifest.profile_hash != config.contract.profile_hash
        or state.manifest.scheduler_policy != config.contract.scheduler
        or state.manifest.scheduler_policy_hash != config.scheduler_policy_hash
    ):
        raise SchedulerStateContractError("prepared state does not bind trusted config-v2")


def _validate_identity(
    config: TrustedSchedulerConfig,
    identity: Mapping[str, Any],
    preflight_id: str,
) -> None:
    try:
        if identity["schema_version"] != SCHEDULER_STATE_SCHEMA_VERSION:
            raise ValueError("schema")
        if identity["preflight_id"] != preflight_id:
            raise ValueError("preflight")
        request_sha256 = _digest(identity["request_sha256"], "request_sha256")
        if not request_sha256:
            raise ValueError("request")
        expected_config = {
            "config_sha256": config.config_sha256,
            "contract_sha256": config.contract_sha256,
            "scheduler_policy_sha256": config.scheduler_policy_hash,
            "profile_id": config.contract.profile_id,
            "profile_hash": config.contract.profile_hash,
        }
        observed_config = {key: identity[key] for key in expected_config}
        if observed_config != expected_config:
            raise ValueError("config")
        manifest = parse_compute_manifest(identity["manifest"])
        prepared = prepare_preflight(manifest)
        expected_state = {
            "preflight_id": prepared.manifest.preflight_id,
            "manifest_sha256": prepared.manifest_sha256,
            "template_sha256": prepared.template_sha256,
            "submission_marker": prepared.submission_marker,
        }
        observed_state = {
            "preflight_id": identity["preflight_id"],
            "manifest_sha256": identity["manifest_sha256"],
            "template_sha256": identity["template_sha256"],
            "submission_marker": identity["submission_marker"],
        }
        if observed_state != expected_state:
            raise ValueError("identity")
        _validate_prepared(config, prepared)
    except (KeyError, TypeError, ValueError, SchedulerPreflightError) as exc:
        raise _invalid("SCHEDULER_ATTEMPT_IDENTITY_INVALID") from exc


def _require_exact_identity(
    loaded: _LoadedAttempt,
    prepared: SchedulerPreflightState,
    request_sha256: str,
) -> None:
    if loaded.request_sha256 != request_sha256:
        raise _conflict("SCHEDULER_REQUEST_HASH_CONFLICT")
    expected = prepare_preflight(prepared.manifest)
    actual = prepare_preflight(loaded.state.manifest)
    if (
        actual.manifest_sha256 != expected.manifest_sha256
        or actual.template_sha256 != expected.template_sha256
        or actual.submission_marker != expected.submission_marker
    ):
        raise _conflict("SCHEDULER_ATTEMPT_IDENTITY_CONFLICT")


def _require_snapshot_cas(
    loaded: _LoadedAttempt,
    snapshot: SchedulerStateSnapshot,
) -> None:
    if (
        loaded.request_sha256 != snapshot.request_sha256
        or loaded.revision != snapshot.revision
        or loaded.journal_sha256 != snapshot.journal_sha256
        or loaded.submit_intent_sha256 != snapshot.submit_intent_sha256
        or loaded.release_intent_sha256 != snapshot.release_intent_sha256
    ):
        raise _conflict("SCHEDULER_STATE_CAS_CONFLICT")


def _validate_intent_base(
    intent: Mapping[str, Any],
    identity: Mapping[str, Any],
    revision_hashes: list[str],
    operation: SchedulerMutationOperation,
) -> None:
    try:
        base_revision = _strict_int(
            intent["base_revision"],
            "base_revision",
            0,
            _MAX_REVISIONS,
        )
        if (
            intent["schema_version"] != SCHEDULER_STATE_SCHEMA_VERSION
            or intent["operation"] != operation
            or intent["preflight_id"] != identity["preflight_id"]
            or intent["request_sha256"] != identity["request_sha256"]
            or intent["config_sha256"] != identity["config_sha256"]
            or intent["contract_sha256"] != identity["contract_sha256"]
            or intent["scheduler_policy_sha256"] != identity["scheduler_policy_sha256"]
            or base_revision >= len(revision_hashes)
            or intent["base_journal_sha256"] != revision_hashes[base_revision]
        ):
            raise ValueError("intent binding")
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid("SCHEDULER_MUTATION_INTENT_INVALID") from exc


def _validate_submit_intent_state(
    intent: Mapping[str, Any],
    prepared: SchedulerPreflightState,
) -> None:
    if (
        intent["base_revision"] != 0
        or intent["manifest_sha256"] != prepared.manifest_sha256
        or intent["template_sha256"] != prepared.template_sha256
        or intent["submission_marker"] != prepared.submission_marker
    ):
        raise SchedulerPreflightError("submit intent does not bind prepared state")


def _validate_release_intent_state(
    intent: Mapping[str, Any],
    held: SchedulerPreflightState,
) -> None:
    if held.held_job is None:
        raise SchedulerPreflightError("release intent lacks held state")
    expected = {
        "job": _job_mapping(held.held_job.job),
        "held_state": held.held_job.state,
        "held_reason": held.held_job.reason,
    }
    observed = {key: intent[key] for key in expected}
    if observed != expected:
        raise SchedulerPreflightError("release intent does not bind exact held evidence")
    _strict_int(intent["elapsed_seconds"], "elapsed_seconds", 0, 2**63 - 1)


def _validated_held(value: SlurmHeldJob) -> SlurmHeldJob:
    if not isinstance(value, SlurmHeldJob):
        raise SchedulerStateContractError("held evidence must use the fixed Slurm contract")
    try:
        return SlurmHeldJob(
            job=SlurmJobRef(
                job_id=value.job.job_id,
                submission_marker=value.job.submission_marker,
                submitted_at=value.job.submitted_at,
            ),
            state=value.state,
            reason=value.reason,
        )
    except SlurmContractError as exc:
        raise SchedulerStateContractError("held evidence is invalid") from exc


def _validate_held_transition(
    state: SchedulerPreflightState,
    held: SlurmHeldJob,
) -> None:
    try:
        record_held_submission(state, held)
    except SchedulerPreflightError as exc:
        raise SchedulerStateContractError(
            "held evidence does not bind the scheduler preflight"
        ) from exc


def _job_mapping(job: SlurmJobRef) -> dict[str, Any]:
    if not isinstance(job, SlurmJobRef):
        raise SchedulerStateContractError("scheduler job reference is invalid")
    return {
        "job_id": job.job_id,
        "submission_marker": job.submission_marker,
        "submitted_at": job.submitted_at,
    }


def _parse_job(value: Any) -> SlurmJobRef:
    mapping = _object(value, "job")
    _exact_fields(mapping, {"job_id", "submission_marker", "submitted_at"}, "job")
    return SlurmJobRef(
        job_id=cast(str, mapping["job_id"]),
        submission_marker=cast(str, mapping["submission_marker"]),
        submitted_at=cast(Any, mapping["submitted_at"]),
    )


def _held_mapping(held: SlurmHeldJob) -> dict[str, Any]:
    return {
        "job": _job_mapping(held.job),
        "state": held.state,
        "reason": held.reason,
    }


def _parse_held(value: Any) -> SlurmHeldJob:
    mapping = _object(value, "held_job")
    _exact_fields(mapping, {"job", "state", "reason"}, "held_job")
    return SlurmHeldJob(
        job=_parse_job(mapping["job"]),
        state=cast(str, mapping["state"]),
        reason=cast(str, mapping["reason"]),
    )


def _observation_mapping(observation: SlurmObservation | None) -> dict[str, Any] | None:
    if observation is None:
        return None
    if not isinstance(observation, SlurmObservation):
        raise SchedulerStateContractError("scheduler observation is invalid")
    return {
        "source": observation.source,
        "job": _job_mapping(observation.job),
        "state": observation.state,
        "exit_code": list(observation.exit_code) if observation.exit_code is not None else None,
        "cancelled_by_uid": observation.cancelled_by_uid,
    }


def _parse_observation(value: Any) -> SlurmObservation | None:
    if value is None:
        return None
    mapping = _object(value, "observation")
    _exact_fields(
        mapping,
        {"source", "job", "state", "exit_code", "cancelled_by_uid"},
        "observation",
    )
    exit_value = mapping["exit_code"]
    exit_code: tuple[int, int] | None
    if exit_value is None:
        exit_code = None
    elif (
        isinstance(exit_value, list)
        and len(exit_value) == 2
        and all(type(item) is int for item in exit_value)
    ):
        exit_code = (exit_value[0], exit_value[1])
    else:
        raise SlurmContractError("persisted scheduler exit code is invalid")
    cancelled = mapping["cancelled_by_uid"]
    if cancelled is not None and type(cancelled) is not int:
        raise SlurmContractError("persisted cancellation uid is invalid")
    return SlurmObservation(
        source=cast(Any, mapping["source"]),
        job=_parse_job(mapping["job"]),
        state=cast(str, mapping["state"]),
        exit_code=exit_code,
        cancelled_by_uid=cancelled,
    )


def _require_phase(state: SchedulerPreflightState, phase: str) -> None:
    if not isinstance(state, SchedulerPreflightState) or state.phase != phase:
        raise _conflict("SCHEDULER_STATE_PHASE_CONFLICT")


def _operation_deadline(timeout_seconds: float) -> float:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise SchedulerStateContractError("scheduler command timeout is invalid")
    return time.monotonic() + timeout_seconds


def _require_live_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise SchedulerStatePreconditionError(
            "SCHEDULER_MUTATION_DEADLINE_EXPIRED",
            "the scheduler mutation deadline expired before durable intent",
        )


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SchedulerStateContractError("scheduler preflight identifier is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SchedulerStateContractError(f"{label} must be a lowercase SHA-256")
    return value


def _optional_digest(value: Any) -> str | None:
    return None if value is None else _digest(value, "invocation_sha256")


def _strict_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SchedulerStateContractError(f"{label} is outside the supported range")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SchedulerStateContractError(f"{label} must be one JSON object")
    return value


def _exact_fields(value: Mapping[str, Any], fields: set[str] | frozenset[str], label: str) -> None:
    if set(value) != set(fields):
        raise SchedulerStateContractError(f"{label} fields do not match the fixed schema")


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                dict(value),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SchedulerStateContractError("durable scheduler record is not canonical JSON") from exc


def _decode_canonical_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _invalid("SCHEDULER_STATE_JSON_INVALID") from exc
    if not isinstance(value, dict) or _canonical_json_bytes(value) != raw:
        raise _invalid("SCHEDULER_STATE_JSON_NONCANONICAL")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate durable scheduler record key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite durable scheduler number is forbidden: {value}")


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written < 1:
            raise OSError("durable scheduler write made no progress")
        remaining = remaining[written:]


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _conflict(reason_code: str) -> SchedulerStateConflictError:
    return SchedulerStateConflictError(
        reason_code,
        "durable scheduler state conflicts with the requested transition",
    )


def _invalid(reason_code: str) -> SchedulerStateInvalidError:
    return SchedulerStateInvalidError(
        reason_code,
        "durable scheduler state is missing, unsafe, or internally inconsistent",
    )


__all__ = [
    "SCHEDULER_STATE_SCHEMA_VERSION",
    "SchedulerMutationPermit",
    "SchedulerMutationPermitError",
    "SchedulerPreflightStore",
    "SchedulerStateBusyError",
    "SchedulerStateCommitUnknown",
    "SchedulerStateConflictError",
    "SchedulerStateContractError",
    "SchedulerStateDeadlineError",
    "SchedulerStateError",
    "SchedulerStateInvalidError",
    "SchedulerStatePreconditionError",
    "SchedulerStateSnapshot",
]
