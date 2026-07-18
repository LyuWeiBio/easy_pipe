"""Bounded shell-free execution for reviewed runtime commands."""

from __future__ import annotations

import math
import os
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

_CHUNK = 64 * 1024
_POLL = 0.05
_GRACE = 0.5


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limit_exceeded: bool = False


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandResult: ...


@dataclass
class _Capture:
    limit: int
    data: bytearray = field(default_factory=bytearray)
    overflow: threading.Event = field(default_factory=threading.Event)

    def consume(self, chunk: bytes) -> None:
        remaining = max(0, self.limit - len(self.data))
        self.data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.overflow.set()


class BoundedCommandRunner:
    """Run fixed argv with bounded output and a minimal explicit environment."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandResult:
        arguments = _validate_command(argv, env, timeout_seconds)
        if output_limit_bytes < 1:
            raise ValueError("output limit must be positive")
        process = subprocess.Popen(
            list(arguments),
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
        assert process.stdout is not None and process.stderr is not None
        stdout = _Capture(output_limit_bytes)
        stderr = _Capture(output_limit_bytes)
        threads = (
            threading.Thread(target=_drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=_drain, args=(process.stderr, stderr), daemon=True),
        )
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        overflow = False
        try:
            for thread in threads:
                thread.start()
            while process.poll() is None:
                if stdout.overflow.is_set() or stderr.overflow.is_set():
                    overflow = True
                    _terminate(process)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _terminate(process)
                    break
                try:
                    process.wait(timeout=min(_POLL, remaining))
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            _terminate(process)
            raise
        finally:
            for thread in threads:
                thread.join(timeout=1.0)
            _close(process.stdout)
            _close(process.stderr)
        assert process.returncode is not None
        return CommandResult(
            argv=arguments,
            return_code=process.returncode,
            stdout=bytes(stdout.data).decode("utf-8", errors="replace"),
            stderr=bytes(stderr.data).decode("utf-8", errors="replace"),
            timed_out=timed_out,
            output_limit_exceeded=overflow or stdout.overflow.is_set() or stderr.overflow.is_set(),
        )


def run_to_logs(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    job_lease_fd: int,
) -> CommandResult:
    """Run a fixed long-lived command, retaining stdout/stderr only on the remote host."""

    arguments = _validate_command(argv, env, timeout_seconds)
    if isinstance(job_lease_fd, bool) or not isinstance(job_lease_fd, int) or job_lease_fd < 0:
        raise ValueError("job lease descriptor must be a non-negative integer")
    lease = os.fstat(job_lease_fd)
    if not stat.S_ISREG(lease.st_mode) or stat.S_IMODE(lease.st_mode) != 0o600:
        raise ValueError("job lease descriptor must identify the private lease file")
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    stdout_fd = os.open(stdout_path, flags, 0o600)
    try:
        stderr_fd = os.open(stderr_path, flags, 0o600)
    except BaseException:
        os.close(stdout_fd)
        raise
    try:
        process = subprocess.Popen(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            cwd=cwd,
            env=dict(env),
            shell=False,
            text=False,
            close_fds=True,
            pass_fds=(job_lease_fd,),
            start_new_session=os.name == "posix",
        )
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate(process)
    assert process.returncode is not None
    return CommandResult(
        argv=arguments,
        return_code=process.returncode,
        stdout="",
        stderr="",
        timed_out=timed_out,
    )


def minimal_environment(
    *,
    executable_paths: Sequence[Path],
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build an allowlisted environment without inheriting credentials or loader hooks."""

    path_directories: list[str] = []
    if any(os.pathsep in str(path.parent) for path in executable_paths):
        raise ValueError("reviewed executable parent cannot contain the PATH separator")
    for directory in (
        *(str(path.parent) for path in executable_paths),
        "/bin",
        "/usr/bin",
    ):
        if directory not in path_directories:
            path_directories.append(directory)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "NXF_ANSI_LOG": "false",
        "NXF_OFFLINE": "true",
        "PATH": os.pathsep.join(path_directories),
    }
    for key, value in (extra or {}).items():
        if key not in {
            "HOME",
            "JAVA_CMD",
            "NXF_HOME",
            "NXF_BIN",
            "NXF_VER",
            "NXF_TEMP",
            "TMPDIR",
            "DOCKER_CONFIG",
            "DOCKER_HOST",
            "APPTAINER_CACHEDIR",
            "APPTAINER_CONFIGDIR",
            "SINGULARITY_CACHEDIR",
            "SINGULARITY_CONFIGDIR",
        }:
            raise ValueError("environment key is not allowlisted")
        if not value or "\x00" in value:
            raise ValueError("environment value is unsafe")
        environment[key] = value
    return environment


def _validate_command(
    argv: Sequence[str], env: Mapping[str, str], timeout_seconds: float
) -> tuple[str, ...]:
    arguments = tuple(argv)
    if not arguments or any(not value or "\x00" in value for value in arguments):
        raise ValueError("argv must be non-empty and NUL-free")
    if not Path(arguments[0]).is_absolute():
        raise ValueError("the reviewed executable path must be absolute")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be positive and finite")
    if any("\x00" in key or "\x00" in value for key, value in env.items()):
        raise ValueError("environment must be NUL-free")
    return arguments


def _drain(pipe: IO[bytes], capture: _Capture) -> None:
    try:
        while chunk := pipe.read(_CHUNK):
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
        process.terminate()
    try:
        process.wait(timeout=_GRACE)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait()


def _close(pipe: IO[bytes]) -> None:
    with suppress(OSError):
        pipe.close()


__all__ = [
    "BoundedCommandRunner",
    "CommandResult",
    "CommandRunner",
    "minimal_environment",
    "run_to_logs",
]
