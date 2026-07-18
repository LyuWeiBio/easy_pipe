"""Bounded, shell-free subprocess execution for local workflow tests."""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

_READ_CHUNK_BYTES = 64 * 1024
_WAIT_SLICE_SECONDS = 0.05
_TERMINATE_GRACE_SECONDS = 0.5


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
        process.wait()


def _close(pipe: IO[bytes]) -> None:
    with suppress(OSError):
        pipe.close()


__all__ = ["CommandResult", "CommandRunner", "SubprocessCommandRunner"]
