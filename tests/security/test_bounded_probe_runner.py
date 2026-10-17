"""Process-level tests for bounded default OpenSSH capture."""

from __future__ import annotations

import io
import subprocess
import sys
import time
from typing import Any

import pytest

import biopipe.probe.bounded as bounded_module
from biopipe.probe.bounded import ProcessStuckError, run_bounded


def test_stdout_overflow_terminates_child_promptly() -> None:
    command = [
        sys.executable,
        "-c",
        (
            "import sys,time;"
            "sys.stdout.buffer.write(b'x'*1048576);"
            "sys.stdout.buffer.flush();"
            "time.sleep(30)"
        ),
    ]

    started = time.monotonic()
    completed = run_bounded(
        command,
        input_text="",
        timeout=10,
        stdout_limit=1024,
        stderr_limit=256,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 3
    assert len(completed.stdout.encode("utf-8")) == 1025
    assert completed.returncode != 0


def test_stderr_capture_is_bounded_while_pipe_is_fully_drained() -> None:
    command = [
        sys.executable,
        "-c",
        "import sys;sys.stderr.buffer.write(b'e'*1048576);sys.stderr.buffer.flush()",
    ]

    completed = run_bounded(
        command,
        input_text="",
        timeout=5,
        stdout_limit=1024,
        stderr_limit=128,
    )

    assert completed.returncode == 0
    assert len(completed.stderr.encode("utf-8")) <= 128
    assert completed.stderr.endswith("...[truncated]")


def test_bounded_runner_preserves_timeout_semantics() -> None:
    command = [sys.executable, "-c", "import time;time.sleep(30)"]

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        run_bounded(
            command,
            input_text="",
            timeout=0.2,
            stdout_limit=1024,
            stderr_limit=256,
        )
    elapsed = time.monotonic() - started

    assert elapsed < 3
    assert exc_info.value.timeout == 0.2


class _StuckPopen:
    """Simulates a D-state child: alive, unkillable, and unreapable."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        self.pid = 2**22
        self.returncode: int | None = None
        self.stdin: Any = io.BytesIO()
        self.stdout: Any = io.BytesIO()
        self.stderr: Any = io.BytesIO()

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired(self.args, timeout)

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


def test_kill_wait_timeout_raises_process_stuck(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bounded_module.subprocess, "Popen", _StuckPopen)
    monkeypatch.setattr(bounded_module, "_TERMINATE_KILL_WAIT_SECONDS", 0.15)

    started = time.monotonic()
    with pytest.raises(ProcessStuckError):
        run_bounded(
            [sys.executable, "-c", "pass"],
            input_text="",
            timeout=0.3,
            stdout_limit=1024,
            stderr_limit=256,
        )
    elapsed = time.monotonic() - started

    # Must give up promptly instead of blocking in wait() forever,
    # and never fabricate a CompletedProcess for the unreaped child.
    assert elapsed < 5
