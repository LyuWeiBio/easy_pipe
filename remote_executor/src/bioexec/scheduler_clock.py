"""Fail-closed boot-relative clock samples for dormant scheduler orchestration.

The scheduler preflight lifecycle must not derive durable elapsed time from the
wall clock or from a caller-provided number.  This module exposes only a stable
boot epoch paired with a boot-relative monotonic nanosecond value.  Sampling
reads the epoch on both sides of the clock read so a reboot observed across the
boundary cannot produce an apparently valid sample.
"""

from __future__ import annotations

import ctypes
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Protocol, cast

_LINUX_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
_MAX_EPOCH_BYTES = 128
_MAX_BOOTTIME_NS = 2**63 - 1
_SAFE_EPOCH = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}", re.ASCII)
_LINUX_BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.ASCII,
)


class SchedulerClockError(RuntimeError):
    """A stable supported scheduler clock sample could not be obtained."""


@dataclass(frozen=True)
class ClockSample:
    """One canonical boot epoch and boot-relative monotonic timestamp."""

    epoch_id: str
    boottime_ns: int

    def __post_init__(self) -> None:
        if type(self.epoch_id) is not str or _SAFE_EPOCH.fullmatch(self.epoch_id) is None:
            raise SchedulerClockError("scheduler clock epoch is not canonical")
        if (
            type(self.boottime_ns) is not int
            or self.boottime_ns < 0
            or self.boottime_ns > _MAX_BOOTTIME_NS
        ):
            raise SchedulerClockError("scheduler boot time is outside its supported range")


class SchedulerClock(Protocol):
    """Structural interface used by the durable scheduler driver."""

    def sample(self) -> ClockSample:
        """Return one stable boot-relative clock sample."""


class SystemSchedulerClock:
    """Read the platform boot epoch and boot-relative monotonic clock."""

    def sample(self) -> ClockSample:
        """Return a double-epoch-checked sample or fail closed."""

        if sys.platform == "linux":
            return _sample_linux()
        if sys.platform == "darwin":
            return _sample_darwin()
        raise SchedulerClockError("scheduler clock is unsupported on this platform")


def _sample_linux() -> ClockSample:
    before = _read_linux_boot_epoch()
    boottime_ns = _linux_boottime_ns()
    after = _read_linux_boot_epoch()
    if before != after:
        raise SchedulerClockError("scheduler clock epoch changed while it was sampled")
    return ClockSample(epoch_id=before, boottime_ns=boottime_ns)


def _read_linux_boot_epoch(path: str = _LINUX_BOOT_ID_PATH) -> str:
    try:
        with open(path, "rb") as handle:
            payload = handle.read(_MAX_EPOCH_BYTES + 1)
    except OSError as exc:
        raise SchedulerClockError("scheduler boot epoch could not be read") from exc
    if len(payload) > _MAX_EPOCH_BYTES or not payload.endswith(b"\n"):
        raise SchedulerClockError("scheduler boot epoch is not canonical")
    raw = payload[:-1]
    if b"\n" in raw or b"\r" in raw:
        raise SchedulerClockError("scheduler boot epoch is not canonical")
    try:
        epoch = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SchedulerClockError("scheduler boot epoch is not canonical") from exc
    if _LINUX_BOOT_ID.fullmatch(epoch) is None or epoch == "00000000-0000-0000-0000-000000000000":
        raise SchedulerClockError("scheduler boot epoch is not canonical")
    return epoch


def _linux_boottime_ns() -> int:
    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if type(clock_id) is not int:
        raise SchedulerClockError("CLOCK_BOOTTIME is unavailable")
    try:
        value = time.clock_gettime_ns(clock_id)
    except (OSError, OverflowError, ValueError) as exc:
        raise SchedulerClockError("CLOCK_BOOTTIME could not be sampled") from exc
    return _validated_boottime_ns(value)


def _sample_darwin() -> ClockSample:
    before = _read_darwin_boot_epoch()
    boottime_ns = _darwin_continuous_time_ns()
    after = _read_darwin_boot_epoch()
    if before != after:
        raise SchedulerClockError("scheduler clock epoch changed while it was sampled")
    return ClockSample(epoch_id=before, boottime_ns=_validated_boottime_ns(boottime_ns))


class _DarwinTimebaseInfo(ctypes.Structure):
    _fields_ = (("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32))


def _darwin_continuous_time_ns() -> int:
    """Read sleep-inclusive Mach continuous time and convert ticks to nanoseconds."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        continuous_time = cast(Any, libc.mach_continuous_time)
        continuous_time.argtypes = ()
        continuous_time.restype = ctypes.c_uint64
        timebase_info = cast(Any, libc.mach_timebase_info)
        timebase_info.argtypes = (ctypes.POINTER(_DarwinTimebaseInfo),)
        timebase_info.restype = ctypes.c_int
        conversion = _DarwinTimebaseInfo()
        result = int(timebase_info(ctypes.byref(conversion)))
        ticks = int(continuous_time())
    except (AttributeError, OSError, OverflowError, TypeError, ValueError) as exc:
        raise SchedulerClockError("the Darwin continuous clock could not be sampled") from exc
    if result != 0 or conversion.numer < 1 or conversion.denom < 1 or ticks < 0:
        raise SchedulerClockError("the Darwin continuous clock could not be sampled")
    value = ticks * int(conversion.numer) // int(conversion.denom)
    return _validated_boottime_ns(value)


class _DarwinTimeval(ctypes.Structure):
    _fields_ = (("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int))


def _read_darwin_boot_epoch() -> str:
    """Read ``kern.boottime`` through libc without spawning ``sysctl``."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        sysctlbyname = cast(Any, libc.sysctlbyname)
        sysctlbyname.argtypes = (
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        )
        sysctlbyname.restype = ctypes.c_int
        value = _DarwinTimeval()
        size = ctypes.c_size_t(ctypes.sizeof(value))
        result = int(
            sysctlbyname(
                b"kern.boottime",
                ctypes.byref(value),
                ctypes.byref(size),
                None,
                0,
            )
        )
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise SchedulerClockError("the Darwin boot epoch could not be read") from exc
    if result != 0 or size.value != ctypes.sizeof(value):
        raise SchedulerClockError("the Darwin boot epoch could not be read")
    seconds = value.tv_sec
    microseconds = value.tv_usec
    if (
        type(seconds) is not int
        or type(microseconds) is not int
        or seconds <= 0
        or seconds > 2**63 - 1
        or not 0 <= microseconds <= 999_999
    ):
        raise SchedulerClockError("the Darwin boot epoch is outside its supported range")
    return f"darwin-{seconds}-{microseconds:06d}"


def _validated_boottime_ns(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_BOOTTIME_NS:
        raise SchedulerClockError("scheduler boot time is outside its supported range")
    return value


__all__ = [
    "ClockSample",
    "SchedulerClock",
    "SchedulerClockError",
    "SystemSchedulerClock",
]
