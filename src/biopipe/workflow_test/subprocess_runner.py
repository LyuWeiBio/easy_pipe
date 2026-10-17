"""Bounded, shell-free subprocess execution for local workflow tests.

Platform assumption: orphan protection via ``prctl(PR_SET_PDEATHSIG)`` is
Linux-only. On other POSIX systems (and non-POSIX systems) the child is
started without a parent-death signal and the pre-existing behavior applies.
"""

from __future__ import annotations

import ctypes
import math
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from ctypes.util import find_library
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

_READ_CHUNK_BYTES = 64 * 1024
_WAIT_SLICE_SECONDS = 0.05
_TERMINATE_GRACE_SECONDS = 0.5
# Bound on the final wait() after SIGKILL. A process that cannot be reaped
# after SIGKILL is stuck in uninterruptible sleep (D-state); waiting forever
# would pin the caller, so the wait is bounded and the stuck condition is
# reported loudly instead of blocking.
_TERMINATE_KILL_WAIT_SECONDS = 5.0


# --- Linux orphan protection -------------------------------------------------
# start_new_session=True detaches the child into its own session, so a SIGKILL
# of the biopipe parent would leave the child (e.g. nextflow) orphaned. On
# Linux the child arms PR_SET_PDEATHSIG=SIGKILL in preexec: the kernel kills
# the child if the forking parent dies. The prctl binding is resolved once at
# import time so the preexec hook itself only performs syscalls.

_PR_SET_PDEATHSIG = 1
_PR_SET_CHILD_SUBREAPER = 36


def _load_prctl() -> Callable[..., int] | None:
    if sys.platform != "linux":
        return None
    try:
        libc_name = find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        prctl.restype = ctypes.c_int
        return prctl
    except OSError:
        return None


_prctl = _load_prctl()


def _preexec_arm_pdeathsig(parent_pid: int) -> None:
    """preexec hook: SIGKILL this child if its parent dies (Linux only).

    Runs in the child after fork(2) and before exec(2). Raises in the child on
    any failure so Popen surfaces it instead of running an unprotected child.
    """
    assert _prctl is not None, "pdeathsig hook used without prctl"
    if _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
    if os.getppid() != parent_pid:
        # The parent died between fork() and prctl(): the death signal would be
        # armed against the wrong parent (init or a sub-reaper). Do not run.
        raise RuntimeError("parent died before PR_SET_PDEATHSIG was armed")


def _pdeathsig_preexec() -> Callable[[], None] | None:
    """Build the preexec hook, or None where prctl is unavailable."""
    if os.name != "posix" or _prctl is None:
        return None
    parent_pid = os.getpid()

    def _hook() -> None:
        _preexec_arm_pdeathsig(parent_pid)

    return _hook


class ProcessStuckError(Exception):
    """A process survived SIGKILL and could not be reaped.

    The child is still alive (typically stuck in D-state). Callers must
    treat this as fatal: never fabricate a result for a process whose
    termination could not be observed.
    """


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Internal bounded command result; stdout/stderr never enter public reports."""

    argv: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limit_exceeded: bool = False


class CommandRunner(Protocol):
    """Injectable command boundary used by unit tests and the real runner."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandResult: ...


@dataclass(slots=True)
class _Capture:
    limit: int
    data: bytearray = field(default_factory=bytearray)
    overflow: threading.Event = field(default_factory=threading.Event)

    def consume(self, chunk: bytes) -> None:
        remaining = max(0, self.limit - len(self.data))
        if remaining:
            self.data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.overflow.set()

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")


class SubprocessCommandRunner:
    """Run one argv array with a deadline and hard output-memory ceilings."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandResult:
        args = tuple(argv)
        if not args or any(not value or "\x00" in value for value in args):
            raise ValueError("argv must contain non-empty NUL-free arguments")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        if output_limit_bytes < 1:
            raise ValueError("output_limit_bytes must be positive")
        if any("\x00" in key or "\x00" in value for key, value in env.items()):
            raise ValueError("subprocess environment must be NUL-free")

        process = subprocess.Popen(
            list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=dict(env),
            shell=False,
            text=False,
            bufsize=0,
            close_fds=True,
            start_new_session=os.name == "posix",
            preexec_fn=_pdeathsig_preexec(),
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_capture = _Capture(output_limit_bytes)
        stderr_capture = _Capture(output_limit_bytes)
        threads = (
            threading.Thread(
                target=_drain,
                args=(process.stdout, stdout_capture),
                name="biopipe-workflow-test-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=_drain,
                args=(process.stderr, stderr_capture),
                name="biopipe-workflow-test-stderr",
                daemon=True,
            ),
        )
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        output_limit_exceeded = False
        started: list[threading.Thread] = []
        try:
            for thread in threads:
                thread.start()
                started.append(thread)
            while process.poll() is None:
                if stdout_capture.overflow.is_set() or stderr_capture.overflow.is_set():
                    output_limit_exceeded = True
                    _terminate(process)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _terminate(process)
                    break
                try:
                    process.wait(timeout=min(_WAIT_SLICE_SECONDS, remaining))
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            _terminate(process)
            raise
        finally:
            for thread in started:
                thread.join(timeout=1.0)
            _close(process.stdout)
            _close(process.stderr)

        output_limit_exceeded = output_limit_exceeded or (
            stdout_capture.overflow.is_set() or stderr_capture.overflow.is_set()
        )
        assert process.returncode is not None
        return CommandResult(
            argv=args,
            return_code=process.returncode,
            stdout=stdout_capture.text(),
            stderr=stderr_capture.text(),
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
        )


def _drain(pipe: IO[bytes], capture: _Capture) -> None:
    try:
        while chunk := pipe.read(_READ_CHUNK_BYTES):
            capture.consume(chunk)
    except (OSError, ValueError):
        pass
    finally:
        _close(pipe)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Terminate the process group, escalating to SIGKILL on the group.

    Raises ProcessStuckError when the process survives SIGKILL and cannot be
    reaped within _TERMINATE_KILL_WAIT_SECONDS: it is stuck (for example in
    uninterruptible D-state sleep) and waiting longer would block forever.
    """
    if process.poll() is not None:
        return
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    else:
        with suppress(ProcessLookupError):
            process.terminate()
    try:
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            with suppress(ProcessLookupError):
                process.kill()
        try:
            process.wait(timeout=_TERMINATE_KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise ProcessStuckError(
                "the process survived SIGKILL and could not be reaped; "
                "it is stuck (for example in uninterruptible D-state sleep)"
            ) from exc


def _close(pipe: IO[bytes]) -> None:
    with suppress(OSError):
        pipe.close()


__all__ = ["CommandResult", "CommandRunner", "ProcessStuckError", "SubprocessCommandRunner"]
