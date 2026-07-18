"""Process-level tests for bounded default OpenSSH capture."""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from biopipe.probe.bounded import run_bounded


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
