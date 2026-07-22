"""Platform and adversarial tests for the dormant scheduler clock."""

from __future__ import annotations

import ctypes
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import bioexec.scheduler_clock as clock_module
from bioexec.scheduler_clock import (
    ClockSample,
    SchedulerClock,
    SchedulerClockError,
    SystemSchedulerClock,
)

_LINUX_EPOCH = "12345678-1234-5678-9abc-123456789abc"


class _FixedClock:
    def sample(self) -> ClockSample:
        return ClockSample(epoch_id="fixed-epoch", boottime_ns=123)


def test_clock_sample_is_frozen_and_scheduler_clock_is_structural() -> None:
    clock: SchedulerClock = _FixedClock()
    sample = clock.sample()

    assert sample == ClockSample(epoch_id="fixed-epoch", boottime_ns=123)
    with pytest.raises(FrozenInstanceError):
        sample.boottime_ns = 456  # type: ignore[misc]


@pytest.mark.parametrize(
    "epoch_id",
    [
        "",
        "-epoch",
        "Uppercase",
        "epoch:1",
        "epoch/1",
        "epoch 1",
        "epoch\n1",
        "époch",
        "a" * 129,
        1,
    ],
)
def test_clock_sample_rejects_noncanonical_epoch_ids(epoch_id: object) -> None:
    with pytest.raises(SchedulerClockError, match="epoch is not canonical"):
        ClockSample(epoch_id=epoch_id, boottime_ns=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("boottime_ns", [True, False, -1, 1.5, "1", 2**63])
def test_clock_sample_rejects_noncanonical_boottime(boottime_ns: object) -> None:
    with pytest.raises(SchedulerClockError, match="outside its supported range"):
        ClockSample(epoch_id="epoch-1", boottime_ns=boottime_ns)  # type: ignore[arg-type]


def test_linux_sample_double_reads_epoch_around_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[str] = []

    def read_epoch() -> str:
        observations.append("epoch")
        return _LINUX_EPOCH

    def read_clock() -> int:
        observations.append("clock")
        return 987_654_321

    monkeypatch.setattr(clock_module.sys, "platform", "linux")
    monkeypatch.setattr(clock_module, "_read_linux_boot_epoch", read_epoch)
    monkeypatch.setattr(clock_module, "_linux_boottime_ns", read_clock)

    assert SystemSchedulerClock().sample() == ClockSample(
        epoch_id=_LINUX_EPOCH,
        boottime_ns=987_654_321,
    )
    assert observations == ["epoch", "clock", "epoch"]


def test_linux_sample_rejects_epoch_change(monkeypatch: pytest.MonkeyPatch) -> None:
    epochs = iter((_LINUX_EPOCH, "abcdefab-cdef-abcd-efab-cdefabcdefab"))
    monkeypatch.setattr(clock_module.sys, "platform", "linux")
    monkeypatch.setattr(clock_module, "_read_linux_boot_epoch", lambda: next(epochs))
    monkeypatch.setattr(clock_module, "_linux_boottime_ns", lambda: 123)

    with pytest.raises(SchedulerClockError, match="epoch changed"):
        SystemSchedulerClock().sample()


def test_linux_epoch_file_requires_exact_lowercase_uuid_and_newline(
    tmp_path: Path,
) -> None:
    path = tmp_path / "boot_id"
    path.write_bytes((_LINUX_EPOCH + "\n").encode("ascii"))

    assert clock_module._read_linux_boot_epoch(str(path)) == _LINUX_EPOCH

    invalid = (
        _LINUX_EPOCH.upper().encode("ascii") + b"\n",
        _LINUX_EPOCH.encode("ascii"),
        (_LINUX_EPOCH + "\n\n").encode("ascii"),
        b"00000000-0000-0000-0000-000000000000\n",
        b"x" * 129,
        b"\xff\n",
    )
    for payload in invalid:
        path.write_bytes(payload)
        with pytest.raises(SchedulerClockError, match="not canonical"):
            clock_module._read_linux_boot_epoch(str(path))


def test_linux_epoch_read_failure_is_sanitized(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(SchedulerClockError, match="could not be read") as captured:
        clock_module._read_linux_boot_epoch(str(missing))

    assert str(missing) not in str(captured.value)


def test_linux_clock_uses_clock_boottime(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[int] = []

    def clock_gettime_ns(clock_id: int) -> int:
        observed.append(clock_id)
        return 456

    monkeypatch.setattr(clock_module.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(clock_module.time, "clock_gettime_ns", clock_gettime_ns)

    assert clock_module._linux_boottime_ns() == 456
    assert observed == [7]


def test_linux_clock_fails_when_clock_boottime_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(clock_module.time, "CLOCK_BOOTTIME", raising=False)

    with pytest.raises(SchedulerClockError, match="CLOCK_BOOTTIME is unavailable"):
        clock_module._linux_boottime_ns()


def test_darwin_sample_double_reads_epoch_around_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[str] = []

    def read_epoch() -> str:
        observations.append("epoch")
        return "darwin-1700000000-123456"

    def read_clock() -> int:
        observations.append("clock")
        return 321

    monkeypatch.setattr(clock_module.sys, "platform", "darwin")
    monkeypatch.setattr(clock_module, "_read_darwin_boot_epoch", read_epoch)
    monkeypatch.setattr(clock_module, "_darwin_continuous_time_ns", read_clock)

    assert SystemSchedulerClock().sample() == ClockSample(
        epoch_id="darwin-1700000000-123456",
        boottime_ns=321,
    )
    assert observations == ["epoch", "clock", "epoch"]


def test_darwin_sample_rejects_epoch_change(monkeypatch: pytest.MonkeyPatch) -> None:
    epochs = iter(("darwin-1700000000-000001", "darwin-1700000001-000001"))
    monkeypatch.setattr(clock_module.sys, "platform", "darwin")
    monkeypatch.setattr(clock_module, "_read_darwin_boot_epoch", lambda: next(epochs))
    monkeypatch.setattr(clock_module, "_darwin_continuous_time_ns", lambda: 123)

    with pytest.raises(SchedulerClockError, match="epoch changed"):
        SystemSchedulerClock().sample()


class _FakeSysctl:
    argtypes: object = None
    restype: object = None

    def __init__(
        self,
        *,
        seconds: int = 1_700_000_000,
        microseconds: int = 42,
        result: int = 0,
        wrong_size: bool = False,
    ) -> None:
        self.seconds = seconds
        self.microseconds = microseconds
        self.result = result
        self.wrong_size = wrong_size
        self.names: list[bytes] = []

    def __call__(
        self,
        name: bytes,
        value_pointer: object,
        size_pointer: object,
        new_value: object,
        new_size: int,
    ) -> int:
        self.names.append(name)
        assert new_value is None
        assert new_size == 0
        value = ctypes.cast(
            value_pointer,
            ctypes.POINTER(clock_module._DarwinTimeval),
        ).contents
        value.tv_sec = self.seconds
        value.tv_usec = self.microseconds
        size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_size_t)).contents
        size.value = 1 if self.wrong_size else ctypes.sizeof(clock_module._DarwinTimeval)
        return self.result


class _FakeLibc:
    def __init__(self, function: _FakeSysctl) -> None:
        self.sysctlbyname = function


class _FakeMachFunction:
    argtypes: object = None
    restype: object = None

    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self, *args: object) -> int:
        del args
        return self.value


class _FakeTimebaseFunction(_FakeMachFunction):
    def __init__(self, *, result: int = 0, numer: int = 1, denom: int = 1) -> None:
        super().__init__(result)
        self.numer = numer
        self.denom = denom

    def __call__(self, pointer: object) -> int:
        value = ctypes.cast(
            pointer,
            ctypes.POINTER(clock_module._DarwinTimebaseInfo),
        ).contents
        value.numer = self.numer
        value.denom = self.denom
        return self.value


class _FakeMachLibc:
    def __init__(self, ticks: int, timebase: _FakeTimebaseFunction) -> None:
        self.mach_continuous_time = _FakeMachFunction(ticks)
        self.mach_timebase_info = timebase


def test_darwin_epoch_uses_ctypes_kern_boottime(monkeypatch: pytest.MonkeyPatch) -> None:
    function = _FakeSysctl()
    monkeypatch.setattr(
        clock_module.ctypes,
        "CDLL",
        lambda _name, use_errno: _FakeLibc(function),
    )

    assert clock_module._read_darwin_boot_epoch() == "darwin-1700000000-000042"
    assert function.names == [b"kern.boottime"]
    assert function.argtypes is not None
    assert function.restype is ctypes.c_int


def test_darwin_continuous_clock_converts_sleep_inclusive_ticks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timebase = _FakeTimebaseFunction(numer=125, denom=3)
    libc = _FakeMachLibc(24, timebase)
    monkeypatch.setattr(clock_module.ctypes, "CDLL", lambda _name, use_errno: libc)

    assert clock_module._darwin_continuous_time_ns() == 1000
    assert libc.mach_continuous_time.argtypes == ()
    assert libc.mach_continuous_time.restype is ctypes.c_uint64
    assert timebase.argtypes is not None
    assert timebase.restype is ctypes.c_int


@pytest.mark.parametrize(
    ("ticks", "timebase"),
    [
        (1, _FakeTimebaseFunction(result=-1)),
        (1, _FakeTimebaseFunction(numer=0)),
        (1, _FakeTimebaseFunction(denom=0)),
        (2**63, _FakeTimebaseFunction(numer=2)),
    ],
)
def test_darwin_continuous_clock_rejects_invalid_or_overflowing_samples(
    monkeypatch: pytest.MonkeyPatch,
    ticks: int,
    timebase: _FakeTimebaseFunction,
) -> None:
    monkeypatch.setattr(
        clock_module.ctypes,
        "CDLL",
        lambda _name, use_errno: _FakeMachLibc(ticks, timebase),
    )

    with pytest.raises(SchedulerClockError):
        clock_module._darwin_continuous_time_ns()


@pytest.mark.parametrize(
    "function",
    [
        _FakeSysctl(result=-1),
        _FakeSysctl(wrong_size=True),
        _FakeSysctl(seconds=0),
        _FakeSysctl(microseconds=-1),
        _FakeSysctl(microseconds=1_000_000),
    ],
)
def test_darwin_epoch_rejects_sysctl_failures(
    monkeypatch: pytest.MonkeyPatch,
    function: _FakeSysctl,
) -> None:
    monkeypatch.setattr(
        clock_module.ctypes,
        "CDLL",
        lambda _name, use_errno: _FakeLibc(function),
    )

    with pytest.raises(SchedulerClockError):
        clock_module._read_darwin_boot_epoch()


def test_unsupported_platform_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clock_module.sys, "platform", "freebsd14")

    with pytest.raises(SchedulerClockError, match="unsupported"):
        SystemSchedulerClock().sample()


@pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="supported host required")
def test_system_scheduler_clock_smoke() -> None:
    sample = SystemSchedulerClock().sample()

    assert ClockSample(sample.epoch_id, sample.boottime_ns) == sample


def test_public_surface_is_closed() -> None:
    assert clock_module.__all__ == [
        "ClockSample",
        "SchedulerClock",
        "SchedulerClockError",
        "SystemSchedulerClock",
    ]
