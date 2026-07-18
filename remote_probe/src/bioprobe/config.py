"""Fail-closed runtime configuration discovery for the remote probe."""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

from .errors import ProbeFailure, ReturnCode

CONFIG_ENV = "BIOPROBE_CONFIG"
MAX_CONFIG_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class ProbeLimits:
    """Server-enforced ceilings; a request may only lower these values."""

    max_depth: int = 6
    max_entries: int = 100_000
    max_runtime_seconds: float = 300.0
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 10_485_760
    max_paths: int = 10_000
    max_path_bytes: int = 4_096
    max_sample_records_total: int = 100_000
    max_content_bytes: int = 268_435_456
    max_input_bytes: int = 268_435_456
    max_fastq_line_bytes: int = 1_048_576


@dataclass(frozen=True, slots=True)
class AllowedRoot:
    """One trusted configured root and its canonical filesystem identity."""

    configured: Path
    canonical: Path
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    """Validated immutable runtime configuration."""

    allowed_roots: tuple[AllowedRoot, ...]
    limits: ProbeLimits = ProbeLimits()
    follow_symlinks: bool = False
    allow_mount_crossing: bool = False
    source: str = "none"

    @classmethod
    def fail_closed_default(cls) -> ProbeConfig:
        """Return a usable health-only configuration with no path access."""

        return cls(allowed_roots=())


def discover_config_path() -> tuple[Path | None, str]:
    """Find the first runtime config without accepting paths from requests."""

    explicit = os.environ.get(CONFIG_ENV)
    if explicit is not None:
        if not explicit or _has_control_characters(explicit):
            raise _config_error("BIOPROBE_CONFIG must be a non-empty safe path")
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            raise _config_error("BIOPROBE_CONFIG must be an absolute path")
        if not path.exists():
            raise _config_error("BIOPROBE_CONFIG does not exist")
        return path, "environment"

    xdg_value = os.environ.get("XDG_CONFIG_HOME")
    xdg_root = Path(xdg_value).expanduser() if xdg_value else Path.home() / ".config"
    candidates = (
        xdg_root / "bioprobe" / "config.json",
        Path.home() / ".bioprobe.json",
        Path("/etc/bioprobe/config.json"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate, "default"
    return None, "none"


def load_config(path: Path | None = None) -> ProbeConfig:
    """Load and strictly validate a JSON config, or return a closed default."""

    if path is None:
        path, source = discover_config_path()
    else:
        path = path.expanduser()
        source = "explicit"
        if not path.is_absolute():
            raise _config_error("config path must be absolute")
    if path is None:
        return ProbeConfig.fail_closed_default()

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    else:
        raise _config_error("this host cannot safely open the probe config")
    try:
        config_fd = os.open(path, flags)
    except OSError as exc:
        raise _config_error("probe config is not readable") from exc
    try:
        file_stat = os.fstat(config_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise _config_error("probe config must be a regular non-symlink file")
        if file_stat.st_size > MAX_CONFIG_BYTES:
            raise _config_error("probe config exceeds the size limit")
        raw = _read_bounded(config_fd, MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise _config_error("probe config is not readable") from exc
    finally:
        os.close(config_fd)
    if len(raw) > MAX_CONFIG_BYTES:
        raise _config_error("probe config exceeds the size limit")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _config_error("probe config must contain strict UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise _config_error("probe config must be a JSON object")
    return _parse_config(payload, source)


def _parse_config(payload: dict[str, Any], source: str) -> ProbeConfig:
    allowed_keys = {
        "schema_version",
        "allowed_roots",
        "limits",
        "follow_symlinks",
        "allow_mount_crossing",
    }
    _reject_unknown(payload, allowed_keys, "config")
    if payload.get("schema_version", "1.0") != "1.0":
        raise _config_error("unsupported probe config schema_version")

    roots_value = payload.get("allowed_roots")
    if not isinstance(roots_value, list) or not roots_value:
        raise _config_error("allowed_roots must be a non-empty array")
    if len(roots_value) > 1024:
        raise _config_error("allowed_roots exceeds the supported entry limit")
    if not all(isinstance(value, str) for value in roots_value):
        raise _config_error("every allowed_roots entry must be a string")

    limits_value = payload.get("limits", {})
    if not isinstance(limits_value, dict):
        raise _config_error("limits must be an object")
    limit_keys = {
        "max_depth",
        "max_entries",
        "max_runtime_seconds",
        "max_request_bytes",
        "max_response_bytes",
        "max_paths",
        "max_path_bytes",
        "max_sample_records_total",
        "max_content_bytes",
        "max_input_bytes",
        "max_fastq_line_bytes",
    }
    _reject_unknown(limits_value, limit_keys, "limits")
    limits = ProbeLimits(
        max_depth=_bounded_int(limits_value, "max_depth", 6, 0, 64),
        max_entries=_bounded_int(limits_value, "max_entries", 100_000, 1, 10_000_000),
        max_runtime_seconds=_bounded_number(
            limits_value, "max_runtime_seconds", 300.0, 0.000001, 3_600.0
        ),
        max_request_bytes=_bounded_int(
            limits_value, "max_request_bytes", 1_048_576, 1_024, 16_777_216
        ),
        max_response_bytes=_bounded_int(
            limits_value, "max_response_bytes", 10_485_760, 512, 67_108_864
        ),
        max_paths=_bounded_int(limits_value, "max_paths", 10_000, 1, 1_000_000),
        max_path_bytes=_bounded_int(limits_value, "max_path_bytes", 4_096, 256, 65_536),
        max_sample_records_total=_bounded_int(
            limits_value,
            "max_sample_records_total",
            100_000,
            1,
            10_000_000,
        ),
        max_content_bytes=_bounded_int(
            limits_value,
            "max_content_bytes",
            268_435_456,
            1,
            1_099_511_627_776,
        ),
        max_input_bytes=_bounded_int(
            limits_value,
            "max_input_bytes",
            268_435_456,
            1,
            1_099_511_627_776,
        ),
        max_fastq_line_bytes=_bounded_int(
            limits_value,
            "max_fastq_line_bytes",
            1_048_576,
            1,
            67_108_864,
        ),
    )

    follow_symlinks = payload.get("follow_symlinks", False)
    allow_mount_crossing = payload.get("allow_mount_crossing", False)
    if not isinstance(follow_symlinks, bool):
        raise _config_error("follow_symlinks must be a boolean")
    if follow_symlinks:
        raise _config_error("M2 does not permit enabling follow_symlinks")
    if not isinstance(allow_mount_crossing, bool):
        raise _config_error("allow_mount_crossing must be a boolean")

    roots = tuple(_load_allowed_root(value, limits.max_path_bytes) for value in roots_value)
    canonical_values = [str(root.canonical) for root in roots]
    if len(canonical_values) != len(set(canonical_values)):
        raise _config_error("allowed_roots contains duplicate canonical paths")
    return ProbeConfig(
        allowed_roots=roots,
        limits=limits,
        follow_symlinks=False,
        allow_mount_crossing=allow_mount_crossing,
        source=source,
    )


def _load_allowed_root(value: str, max_path_bytes: int) -> AllowedRoot:
    _validate_config_path(value, max_path_bytes)
    configured = Path(os.path.normpath(value))
    try:
        raw_stat = configured.lstat()
        canonical = configured.resolve(strict=True)
        canonical_stat = canonical.stat()
        final_raw_stat = configured.lstat()
    except (OSError, RuntimeError) as exc:
        raise _config_error("an allowed root does not exist or is unreadable") from exc
    if stat.S_ISLNK(raw_stat.st_mode) or stat.S_ISLNK(final_raw_stat.st_mode):
        raise _config_error("an allowed root must not itself be a symlink")
    initial_identity = (raw_stat.st_dev, raw_stat.st_ino)
    final_identity = (final_raw_stat.st_dev, final_raw_stat.st_ino)
    canonical_identity = (canonical_stat.st_dev, canonical_stat.st_ino)
    if initial_identity != final_identity or final_identity != canonical_identity:
        raise _config_error("an allowed root changed while configuration was loading")
    if not stat.S_ISDIR(canonical_stat.st_mode):
        raise _config_error("every allowed root must be a directory")
    return AllowedRoot(
        configured=configured,
        canonical=canonical,
        device=canonical_stat.st_dev,
        inode=canonical_stat.st_ino,
    )


def _read_bounded(file_descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(file_descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_config_path(value: str, max_path_bytes: int) -> None:
    if not value or _has_control_characters(value) or _has_surrogate(value):
        raise _config_error("allowed root contains forbidden characters")
    if len(value.encode("utf-8")) > max_path_bytes:
        raise _config_error("allowed root exceeds max_path_bytes")
    path = PurePath(value)
    if not path.is_absolute():
        raise _config_error("allowed roots must be absolute paths")
    if ".." in path.parts:
        raise _config_error("allowed roots must not contain parent traversal")


def _bounded_int(values: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = values.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _config_error(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise _config_error(f"{key} is outside its supported range")
    return int(value)


def _bounded_number(
    values: dict[str, Any], key: str, default: float, minimum: float, maximum: float
) -> float:
    value = values.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config_error(f"{key} must be a number")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise _config_error(f"{key} is outside its supported range")
    return number


def _reject_unknown(values: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise _config_error(f"{label} contains unsupported fields")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _config_error(message: str) -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.PROTOCOL_ERROR,
        "CONFIG_INVALID",
        message,
        remediation=["Install a valid JSON config in a documented discovery location."],
    )


__all__ = [
    "CONFIG_ENV",
    "AllowedRoot",
    "ProbeConfig",
    "ProbeLimits",
    "discover_config_path",
    "load_config",
]
