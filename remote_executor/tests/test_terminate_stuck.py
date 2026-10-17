"""Stuck-process (post-SIGKILL wait timeout) behavior for the remote executor."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

import bioexec.commands as commands_module
import bioexec.runner as runner_module
from bioexec.commands import ProcessStuckError, _terminate, run_to_logs
from bioexec.config import AgentConfig
from bioexec.errors import ReturnCode
from bioexec.state import StateStore


class _StuckProcess:
    """Simulates a D-state process: alive, unkillable, and unreapable."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        self.pid = 2**22  # bogus; killpg raises ProcessLookupError (suppressed)
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired(self.args, timeout)

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


def test_terminate_raises_process_stuck_after_kill_wait_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands_module, "_TERMINATE_KILL_WAIT_SECONDS", 0.15)
    started = time.monotonic()
    with pytest.raises(ProcessStuckError):
        _terminate(_StuckProcess())
    elapsed = time.monotonic() - started
    # Must give up promptly instead of blocking in wait() forever.
    assert elapsed < 3


def test_terminate_reaps_sigkill_only_process_without_stuck() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "sys.stdout.write('ready\\n'); sys.stdout.flush(); "
            "time.sleep(60)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name == "posix",
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline() == b"ready\n"
        _terminate(process)  # must not raise
    finally:
        with suppress(Exception):
            process.kill()
        process.wait(timeout=5)
    assert process.returncode == -signal.SIGKILL


def test_run_to_logs_propagates_stuck_instead_of_hanging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease_path = tmp_path / "lease"
    lease_path.write_bytes(b"")
    lease_path.chmod(0o600)
    lease_fd = os.open(lease_path, os.O_RDWR)
    monkeypatch.setattr(commands_module, "_TERMINATE_KILL_WAIT_SECONDS", 0.15)
    monkeypatch.setattr(commands_module.subprocess, "Popen", _StuckProcess)
    try:
        started = time.monotonic()
        with pytest.raises(ProcessStuckError):
            run_to_logs(
                (sys.executable, "-c", "pass"),
                cwd=tmp_path,
                env={},
                timeout_seconds=0.05,
                stdout_path=tmp_path / "stdout.log",
                stderr_path=tmp_path / "stderr.log",
                job_lease_fd=lease_fd,
            )
        assert time.monotonic() - started < 5
    finally:
        os.close(lease_fd)


def test_execute_run_marks_supervisor_stuck_and_releases_lease(
    agent_config: AgentConfig, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = StateStore(agent_config.state_root)
    run_id = "run-stuck-marking"
    run_directory = state.create_run_directory(run_id)
    state.create_supervisor_lease(run_id)
    lease_fd = state.acquire_supervisor_lease(run_id)
    command_hash = "1" * 64
    environment_hash = "2" * 64
    record = {
        "run_id": run_id,
        "status": "submitted",
        "command_hash": command_hash,
        "environment_hash": environment_hash,
    }
    state.create("runs", run_id, record)

    for name in (
        "verify_deployment",
        "recheck_input_records",
        "recheck_container_artifacts",
        "_recheck_run_directories",
        "_verify_run_executables",
    ):
        monkeypatch.setattr(runner_module, name, lambda *args, **kwargs: None)

    def _stuck(*args: Any, **kwargs: Any) -> Any:
        raise ProcessStuckError("synthetic stuck job")

    monkeypatch.setattr(runner_module, "run_to_logs", _stuck)

    runner_module._execute_run(
        run_id=run_id,
        record=record,
        state=state,
        argv=("true",),
        environment={},
        cwd=tmp_path,
        run_directory=run_directory,
        timeout_seconds=1,
        config=agent_config,
        preflight={"container_engine": "docker"},
        deployment={},
        lease_fd=lease_fd,
    )

    final = state.read("runs", run_id)
    assert final["status"] == "failed"
    assert final["failure_code"] == "RUN_SUPERVISOR_STUCK"
    assert final["return_code"] == int(ReturnCode.RUN_FAILED)
    # The supervisor released its own lease descriptor on the way out...
    with pytest.raises(OSError):
        os.fstat(lease_fd)
    # ...so the recovery path can now take the lock.
    with state.try_supervisor_recovery_lease(run_id) as acquired:
        assert acquired is True
