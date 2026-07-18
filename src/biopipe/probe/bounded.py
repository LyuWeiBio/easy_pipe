"""Memory-bounded subprocess capture for the default OpenSSH transport."""

from __future__ import annotations

import math
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import IO, Final

_READ_CHUNK_BYTES: Final[int] = 64 * 1024
_WAIT_SLICE_SECONDS: Final[float] = 0.05
_TERMINATE_GRACE_SECONDS: Final[float] = 0.25
_TRUNCATION_MARKER: Final[bytes] = b"...[truncated]"


@dataclass(slots=True)
class _CaptureBuffer:
    limit: int
    stop_on_overflow: bool
    data: bytearray = field(default_factory=bytearray)
    overflow: threading.Event = field(default_factory=threading.Event)

    def consume(self, chunk: bytes) -> None:
        """Retain at most ``limit + 1`` bytes and flag additional output."""

        sentinel_limit = self.limit + 1 if self.stop_on_overflow else self.limit
        remaining = max(0, sentinel_limit - len(self.data))
        if remaining:
            self.data.extend(chunk[:remaining])
        if len(chunk) > remaining or (self.stop_on_overflow and len(self.data) > self.limit):
            self.overflow.set()

    def decoded(self) -> str:
        data = bytes(self.data)
        if self.overflow.is_set() and not self.stop_on_overflow:
            data = _bounded_with_marker(data, self.limit)
        return data.decode("utf-8", errors="replace")


def run_bounded(
    args: Sequence[str],
    *,
    input_text: str,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an argument array with bounded pipe readers and no shell.

    Stdout overflow terminates the child promptly and returns a ``limit + 1``
    sentinel so the caller can map it to its stable output-limit error. Stderr is
    continuously drained but only a bounded, marked prefix is retained.
    """

    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive")
    if stdout_limit < 1 or stderr_limit < 1:
        raise ValueError("capture limits must be positive")
    input_bytes = input_text.encode("utf-8")
    process = subprocess.Popen(
        list(args),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        text=False,
        bufsize=0,
        env=None if env is None else dict(env),
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_capture = _CaptureBuffer(stdout_limit, stop_on_overflow=True)
    stderr_capture = _CaptureBuffer(stderr_limit, stop_on_overflow=False)
    threads = (
        threading.Thread(
            target=_write_input,
            args=(process.stdin, input_bytes),
            name="biopipe-ssh-stdin",
            daemon=True,
        ),
        threading.Thread(
            target=_drain_output,
            args=(process.stdout, stdout_capture),
            name="biopipe-ssh-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=_drain_output,
            args=(process.stderr, stderr_capture),
            name="biopipe-ssh-stderr",
            daemon=True,
        ),
    )
    deadline = time.monotonic() + timeout
    timed_out = False
    started_threads: list[threading.Thread] = []
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        while process.poll() is None:
            if stdout_capture.overflow.is_set():
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
        _close_pipe(process.stdin)
        for thread in started_threads:
            thread.join(timeout=1.0)
        _close_pipe(process.stdout)
        _close_pipe(process.stderr)

    stdout = stdout_capture.decoded()
    stderr = stderr_capture.decoded()
    if timed_out:
        raise subprocess.TimeoutExpired(
            cmd=list(args),
            timeout=timeout,
            output=stdout,
            stderr=stderr,
        )
    assert process.returncode is not None
    return subprocess.CompletedProcess(
        args=list(args),
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _write_input(pipe: IO[bytes], data: bytes) -> None:
    try:
        view = memoryview(data)
        for offset in range(0, len(view), _READ_CHUNK_BYTES):
            pipe.write(view[offset : offset + _READ_CHUNK_BYTES])
        pipe.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        _close_pipe(pipe)


def _drain_output(pipe: IO[bytes], capture: _CaptureBuffer) -> None:
    try:
        while chunk := pipe.read(_READ_CHUNK_BYTES):
            capture.consume(chunk)
    except (OSError, ValueError):
        pass
    finally:
        _close_pipe(pipe)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        process.terminate()
    try:
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            process.kill()
        process.wait()


def _bounded_with_marker(data: bytes, limit: int) -> bytes:
    if limit <= len(_TRUNCATION_MARKER):
        return _TRUNCATION_MARKER[:limit]
    return data[: limit - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def _close_pipe(pipe: IO[bytes]) -> None:
    with suppress(OSError):
        pipe.close()


__all__ = ["run_bounded"]
