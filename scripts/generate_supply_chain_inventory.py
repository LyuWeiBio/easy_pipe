#!/usr/bin/env python3
"""Generate or offline-verify create-only M6.1 supply-chain evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.parse
import zipfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any, Final, NoReturn

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from biopipe.release_evidence.checksums import (  # noqa: E402
    checksum_payloads,
    parse_checksum_manifest,
)
from biopipe.release_evidence.store import EvidenceBundleStore  # noqa: E402

FORMAT_VERSION: Final[str] = "1"
SOURCE_DATE_EPOCH: Final[int] = 315_532_800
CHANNELS: Final[tuple[str, ...]] = ("conda-forge", "bioconda")
CHANNEL_HOST: Final[str] = "conda.anaconda.org"
TARGETS: Final[dict[str, tuple[str, ...]]] = {
    "linux-64": (
        "__unix=0=0",
        "__linux=5.15=0",
        "__glibc=2.17=0",
        "__archspec=1=x86_64-v2",
    ),
    "osx-arm64": ("__unix=0=0", "__osx=11.0=0", "__archspec=1=arm64"),
}
EXPECTED_CONTAINERS: Final[dict[str, dict[str, object]]] = {
    "fastp": {
        "component_ids": ["fastp_paired_v1", "fastp_single_v1"],
        "declared_component_license": "MIT",
        "digest": "sha256:cbbe2402b6b6704df470d7d77dcb498eefd5bcd01f4c38be0ec69899e79ac134",
        "image": "quay.io/biocontainers/fastp:1.3.6--h43da1c4_0",
        "version": "1.3.6",
    },
    "fastqc": {
        "component_ids": ["fastqc_post_trim_v1", "fastqc_raw_v1"],
        "declared_component_license": "GPL-3.0-or-later",
        "digest": "sha256:e194048df39c3145d9b4e0a14f4da20b59d59250465b6f2a9cb698445fd45900",
        "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
        "version": "0.12.1",
    },
    "multiqc": {
        "component_ids": ["multiqc_v1"],
        "declared_component_license": "GPL-3.0-or-later",
        "digest": "sha256:b65e3fe879df27b92334dda0fd987a6e21bdee09a2848551d4f287099a93b7ac",
        "image": "quay.io/biocontainers/multiqc:1.35--pyhdfd78af_1",
        "version": "1.35",
    },
}
OUTPUT_FILES: Final[frozenset[str]] = frozenset(
    {
        "README.md",
        "SHA256SUMS",
        "containers.json",
        "direct-dependencies.json",
        "linux-64.explicit.txt",
        "linux-64.inventory.json",
        "lock-metadata.json",
        "osx-arm64.explicit.txt",
        "osx-arm64.inventory.json",
        "remote-zipapps.json",
    }
)
JSON_FILES: Final[frozenset[str]] = frozenset(
    name for name in OUTPUT_FILES if name.endswith(".json")
)
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
CONDA_NAME = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,127}$")
CONDA_FILENAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254}$")
SAFE_VALUE = re.compile(r"^[ -~]{1,512}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION_ASSIGNMENT = re.compile(r"^([a-z0-9][a-z0-9_.-]*)=([^=\s]{1,128})$")
SOLVER_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
VERSION_SOURCE = re.compile(r'^__version__\s*=\s*"([A-Za-z0-9.+_-]{1,64})"$', re.MULTILINE)
MAX_SOLVER_OUTPUT_BYTES: Final[int] = 8 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES: Final[int] = 4 * 1024 * 1024
MAX_ZIPAPP_BYTES: Final[int] = 16 * 1024 * 1024
MAX_ZIP_MEMBERS: Final[int] = 128


class SupplyChainError(RuntimeError):
    """A stable fail-closed generation or verification failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> NoReturn:
    raise SupplyChainError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _load_json(payload: bytes) -> Any:
    if not payload or len(payload) > MAX_BUNDLE_FILE_BYTES or b"\r" in payload:
        _fail("INVALID_JSON_ARTIFACT")
    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError("INVALID_JSON_ARTIFACT") from exc


def _read_source(path: Path, *, maximum: int = MAX_BUNDLE_FILE_BYTES) -> bytes:
    raw = os.fspath(path)
    original = Path(raw)
    if not raw or "\x00" in raw or any(part == ".." for part in original.parts):
        _fail("UNSAFE_SOURCE_INPUT")
    absolute = Path(os.path.abspath(raw))
    parts = absolute.parts
    directory_descriptor: int | None = None
    descriptor: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        directory_descriptor = os.open(parts[0], flags)
        for component in parts[1:-1]:
            next_descriptor = os.open(component, flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            _fail("UNSAFE_SOURCE_INPUT")
        payload = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - len(payload))):
            payload.extend(chunk)
            if len(payload) > maximum:
                _fail("UNSAFE_SOURCE_INPUT")
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(payload) != metadata.st_size or any(
            getattr(metadata, field) != getattr(after, field) for field in stable_fields
        ):
            _fail("UNSTABLE_SOURCE_INPUT")
        return bytes(payload)
    except SupplyChainError:
        raise
    except OSError as exc:
        raise SupplyChainError("UNSAFE_SOURCE_INPUT") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


def _environment_definition(repository: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_source(repository / "environments" / "m4-test.yml")
    try:
        value = yaml.safe_load(payload)
    except yaml.YAMLError as exc:
        raise SupplyChainError("INVALID_ENVIRONMENT_DEFINITION") from exc
    if not isinstance(value, dict) or set(value) != {"name", "channels", "dependencies"}:
        _fail("INVALID_ENVIRONMENT_DEFINITION")
    if value["name"] != "easy-pipe-m4" or value["channels"] != list(CHANNELS):
        _fail("INVALID_ENVIRONMENT_DEFINITION")
    dependencies = value["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        _fail("INVALID_ENVIRONMENT_DEFINITION")
    direct: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in dependencies:
        if not isinstance(raw, str):
            _fail("NON_CONDA_DEPENDENCY_REJECTED")
        match = VERSION_ASSIGNMENT.fullmatch(raw)
        if match is None:
            _fail("DIRECT_DEPENDENCY_NOT_EXACT")
        name, version = match.groups()
        if name in seen:
            _fail("DUPLICATE_DIRECT_DEPENDENCY")
        seen.add(name)
        direct.append({"name": name, "version": version})
    if len(direct) != 20:
        _fail("DIRECT_DEPENDENCY_SET_CHANGED")
    return {"name": value["name"], "channels": list(CHANNELS), "direct": direct}, payload


def _safe_requirement(value: object) -> str:
    if not isinstance(value, str) or SAFE_VALUE.fullmatch(value) is None:
        _fail("UNSAFE_PROJECT_REQUIREMENT")
    if any(token in value for token in ("@", "/", "\\", "://")):
        _fail("UNSAFE_PROJECT_REQUIREMENT")
    return value


def _direct_dependencies(repository: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    environment, environment_payload = _environment_definition(repository)
    project_payload = _read_source(repository / "pyproject.toml")
    try:
        project = tomllib.loads(project_payload.decode("utf-8"))
        runtime = [_safe_requirement(item) for item in project["project"]["dependencies"]]
        development = [
            _safe_requirement(item) for item in project["project"]["optional-dependencies"]["dev"]
        ]
        build = [_safe_requirement(item) for item in project["build-system"]["requires"]]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChainError("INVALID_PROJECT_DEPENDENCIES") from exc
    result = {
        "format_version": FORMAT_VERSION,
        "sources": {
            "environment": {
                "path": "environments/m4-test.yml",
                "sha256": _sha256(environment_payload),
            },
            "project": {"path": "pyproject.toml", "sha256": _sha256(project_payload)},
        },
        "reference_environment": environment,
        "project": {
            "build": build,
            "development": development,
            "runtime": runtime,
        },
        "remote_zipapps": {
            "dependency_model": "python-standard-library-only",
            "third_party_python_dependencies": [],
        },
    }
    return result, environment["direct"]


def _controlled_environment(root: Path, platform: str) -> dict[str, str]:
    home = root / "home"
    temporary = root / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    environment = {
        "CONDA_SUBDIR": platform,
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(temporary),
    }
    if platform == "linux-64":
        environment["CONDA_OVERRIDE_LINUX"] = "5.15"
        environment["CONDA_OVERRIDE_GLIBC"] = "2.17"
    elif platform == "osx-arm64":
        environment["CONDA_OVERRIDE_OSX"] = "11.0"
    else:
        _fail("UNSUPPORTED_TARGET_PLATFORM")
    return environment


def _run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()

    def consume(stream: Any, target: bytearray) -> None:
        while chunk := stream.read(64 * 1024):
            if len(target) + len(chunk) > MAX_SOLVER_OUTPUT_BYTES:
                overflow.set()
                if process is not None:
                    with suppress(OSError):
                        process.kill()
                return
            target.extend(chunk)

    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        if process.stdout is None or process.stderr is None:
            _fail("BOUNDED_SUBPROCESS_FAILED")
        readers = (
            threading.Thread(target=consume, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=consume, args=(process.stderr, stderr), daemon=True),
        )
        for reader in readers:
            reader.start()
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            _fail("BOUNDED_SUBPROCESS_FAILED")
        finally:
            for reader in readers:
                reader.join(timeout=10)
        if any(reader.is_alive() for reader in readers):
            process.kill()
            _fail("BOUNDED_SUBPROCESS_FAILED")
    except SupplyChainError:
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SupplyChainError("BOUNDED_SUBPROCESS_FAILED") from exc
    if (
        return_code != 0
        or overflow.is_set()
        or not stdout
        or len(stdout) > MAX_SOLVER_OUTPUT_BYTES
        or len(stderr) > MAX_SOLVER_OUTPUT_BYTES
    ):
        _fail("BOUNDED_SUBPROCESS_FAILED")
    return bytes(stdout)


def _solver_identity(
    micromamba: Path, root: Path, environment: Mapping[str, str]
) -> dict[str, str]:
    version_payload = _run_bounded(
        [str(micromamba), "--version"], cwd=root, environment=environment, timeout=10
    )
    try:
        version = version_payload.decode("ascii").strip()
    except UnicodeError as exc:
        raise SupplyChainError("INVALID_SOLVER_IDENTITY") from exc
    if SOLVER_VERSION.fullmatch(version) is None:
        _fail("INVALID_SOLVER_IDENTITY")
    info_payload = _run_bounded(
        [str(micromamba), "info", "--json", "--no-rc", "-r", str(root / "mamba-root")],
        cwd=root,
        environment=environment,
        timeout=30,
    )
    info = _load_json(info_payload)
    if not isinstance(info, dict):
        _fail("INVALID_SOLVER_IDENTITY")
    micromamba_version = info.get("micromamba version")
    libmamba_version = info.get("libmamba version")
    if (
        micromamba_version != version
        or not isinstance(libmamba_version, str)
        or SOLVER_VERSION.fullmatch(libmamba_version) is None
    ):
        _fail("INVALID_SOLVER_IDENTITY")
    return {
        "executable_sha256": _sha256(_read_source(micromamba, maximum=128 * 1024 * 1024)),
        "libmamba_version": libmamba_version,
        "name": "micromamba",
        "version": version,
    }


def _virtual_packages(
    micromamba: Path,
    root: Path,
    environment: Mapping[str, str],
    platform: str,
) -> list[str]:
    payload = _run_bounded(
        [str(micromamba), "info", "--json", "--no-rc", "-r", str(root / "mamba-root")],
        cwd=root,
        environment=environment,
        timeout=30,
    )
    value = _load_json(payload)
    if not isinstance(value, dict) or value.get("platform") != platform:
        _fail("VIRTUAL_PACKAGE_PLATFORM_MISMATCH")
    observed = value.get("virtual packages")
    if not isinstance(observed, list) or not all(isinstance(item, str) for item in observed):
        _fail("INVALID_VIRTUAL_PACKAGE_SET")
    expected = set(TARGETS[platform])
    if set(observed) != expected or len(observed) != len(expected):
        _fail("INVALID_VIRTUAL_PACKAGE_SET")
    return list(TARGETS[platform])


def _validate_url(url: str, *, target_platform: str) -> tuple[str, str, str]:
    if not isinstance(url, str) or len(url) > 1024 or any(ord(char) < 32 for char in url):
        _fail("UNSAFE_PACKAGE_URL")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != CHANNEL_HOST
        or parsed.netloc != CHANNEL_HOST
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or urllib.parse.unquote(parsed.path) != parsed.path
    ):
        _fail("UNSAFE_PACKAGE_URL")
    parts = parsed.path.split("/")
    if len(parts) != 4 or parts[0] != "":
        _fail("UNSAFE_PACKAGE_URL")
    channel, subdir, filename = parts[1:]
    if channel not in CHANNELS or subdir not in {target_platform, "noarch"}:
        _fail("UNSAFE_PACKAGE_URL")
    if (
        CONDA_FILENAME.fullmatch(filename) is None
        or not filename.endswith((".conda", ".tar.bz2"))
        or ".." in filename
    ):
        _fail("UNSAFE_PACKAGE_URL")
    return channel, subdir, filename


def _safe_record_text(value: object, *, code: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        _fail(code)
    return value


def _normalize_records(
    records: object,
    *,
    target_platform: str,
    direct: Sequence[Mapping[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(records, list) or not records or len(records) > 1024:
        _fail("INVALID_SOLVER_TRANSACTION")
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw in records:
        if not isinstance(raw, dict):
            _fail("INVALID_PACKAGE_RECORD")
        name = _safe_record_text(raw.get("name"), code="INVALID_PACKAGE_RECORD", maximum=128)
        if CONDA_NAME.fullmatch(name) is None or name in names:
            _fail("INVALID_PACKAGE_RECORD")
        names.add(name)
        version = _safe_record_text(raw.get("version"), code="INVALID_PACKAGE_RECORD", maximum=128)
        build = _safe_record_text(
            raw.get("build_string") or raw.get("build"),
            code="INVALID_PACKAGE_RECORD",
            maximum=256,
        )
        url = _safe_record_text(raw.get("url"), code="UNSAFE_PACKAGE_URL", maximum=1024)
        channel, subdir, filename = _validate_url(url, target_platform=target_platform)
        extension = ".conda" if filename.endswith(".conda") else ".tar.bz2"
        if filename != f"{name}-{version}-{build}{extension}":
            _fail("PACKAGE_FILENAME_METADATA_MISMATCH")
        if raw.get("subdir") != subdir or raw.get("fn") != filename:
            _fail("PACKAGE_URL_METADATA_MISMATCH")
        expected_channel = f"https://{CHANNEL_HOST}/{channel}/{subdir}"
        if raw.get("channel") != expected_channel:
            _fail("PACKAGE_URL_METADATA_MISMATCH")
        md5 = raw.get("md5")
        sha256 = raw.get("sha256")
        if not isinstance(md5, str) or HEX32.fullmatch(md5) is None:
            _fail("INVALID_PACKAGE_HASH")
        if not isinstance(sha256, str) or HEX64.fullmatch(sha256) is None:
            _fail("INVALID_PACKAGE_HASH")
        build_number = raw.get("build_number")
        size = raw.get("size")
        timestamp = raw.get("timestamp")
        if (
            type(build_number) is not int
            or build_number < 0
            or type(size) is not int
            or not 0 < size <= 16 * 1024 * 1024 * 1024
            or type(timestamp) is not int
            or timestamp <= 0
        ):
            _fail("INVALID_PACKAGE_RECORD")
        license_value = _safe_record_text(
            raw.get("license"), code="MISSING_PACKAGE_LICENSE", maximum=512
        )
        depends = raw.get("depends")
        if depends is None:
            depends = []
        elif not isinstance(depends, list) or len(depends) > 512:
            _fail("INVALID_PACKAGE_DEPENDENCIES")
        dependencies = sorted(
            _safe_record_text(item, code="INVALID_PACKAGE_DEPENDENCIES") for item in depends
        )
        normalized.append(
            {
                "build": build,
                "build_number": build_number,
                "channel": channel,
                "depends": dependencies,
                "filename": filename,
                "license": license_value,
                "md5": md5,
                "name": name,
                "sha256": sha256,
                "size": size,
                "subdir": subdir,
                "timestamp_ms": timestamp,
                "url": url,
                "version": version,
            }
        )
    by_name = {item["name"]: item for item in normalized}
    virtual_names = {item.split("=", 1)[0] for item in TARGETS[target_platform]}
    allowed_dependency_names = set(by_name) | virtual_names
    for item in normalized:
        for dependency in item["depends"]:
            dependency_name = dependency.split(maxsplit=1)[0]
            if (
                CONDA_NAME.fullmatch(dependency_name) is None
                or dependency_name not in allowed_dependency_names
            ):
                _fail("PACKAGE_DEPENDENCY_NOT_LOCKED")
    for requirement in direct:
        candidate = by_name.get(requirement["name"])
        if candidate is None or candidate["version"] != requirement["version"]:
            _fail("DIRECT_DEPENDENCY_PIN_MISMATCH")
    return sorted(normalized, key=lambda item: item["name"])


def _solve_platform(
    micromamba: Path,
    repository: Path,
    platform: str,
    direct: Sequence[Mapping[str, str]],
    source_sha256: str,
) -> tuple[bytes, bytes, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix=f"easy-pipe-{platform}-solve-") as raw_temporary:
        temporary = Path(raw_temporary).resolve()
        root = temporary / "mamba-root"
        prefix = temporary / "prefix"
        (root / "pkgs").mkdir(parents=True, mode=0o700)
        environment = _controlled_environment(temporary, platform)
        virtual_packages = _virtual_packages(micromamba, temporary, environment, platform)
        argv = [
            str(micromamba),
            "create",
            "--dry-run",
            "--json",
            "--no-rc",
            "-r",
            str(root),
            "-p",
            str(prefix),
            "--platform",
            platform,
            "--override-channels",
            "--strict-channel-priority",
        ]
        for channel in CHANNELS:
            argv.extend(("-c", channel))
        argv.extend(f"{item['name']}={item['version']}" for item in direct)
        payload = _run_bounded(argv, cwd=repository, environment=environment, timeout=900)
        transaction = _load_json(payload)
        if (
            not isinstance(transaction, dict)
            or transaction.get("success") is not True
            or transaction.get("dry_run") is not True
        ):
            _fail("INVALID_SOLVER_TRANSACTION")
        actions = transaction.get("actions")
        if not isinstance(actions, dict):
            _fail("INVALID_SOLVER_TRANSACTION")
        records = _normalize_records(actions.get("LINK"), target_platform=platform, direct=direct)
    explicit = _render_explicit(platform, records)
    inventory_value = {
        "direct_dependencies": list(direct),
        "format_version": FORMAT_VERSION,
        "native_runtime_validation": {
            "reason": "generated_by_cross_platform_metadata_solve_only",
            "status": "pending",
        },
        "packages": records,
        "resolution_status": "resolved_cross_platform",
        "source_environment_sha256": source_sha256,
        "target_platform": platform,
        "virtual_packages": virtual_packages,
    }
    inventory = _json_bytes(inventory_value)
    summary = {
        "explicit_lock": {
            "path": f"environments/locks/{platform}.explicit.txt",
            "sha256": _sha256(explicit),
        },
        "inventory": {
            "path": f"environments/locks/{platform}.inventory.json",
            "sha256": _sha256(inventory),
        },
        "native_runtime_validation": "pending",
        "package_count": len(records),
        "resolution_status": "resolved_cross_platform",
        "target_platform": platform,
        "virtual_packages": virtual_packages,
    }
    return explicit, inventory, summary


def _render_explicit(platform: str, records: Sequence[Mapping[str, Any]]) -> bytes:
    lines = [
        "# Generated create-only from environments/m4-test.yml; do not edit.",
        f"# target-platform: {platform}",
        "# native-runtime-validation: pending",
        "@EXPLICIT",
    ]
    lines.extend(f"{record['url']}#{record['md5']}" for record in records)
    return ("\n".join(lines) + "\n").encode("ascii")


def _version_from_source(path: Path) -> str:
    payload = _read_source(path, maximum=64 * 1024)
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise SupplyChainError("INVALID_ZIPAPP_VERSION") from exc
    match = VERSION_SOURCE.search(text)
    if match is None:
        _fail("INVALID_ZIPAPP_VERSION")
    return match.group(1)


def _validate_zip_member_name(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if (
        not 0 < len(name) <= 256
        or pure.is_absolute()
        or pure.as_posix() != name
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in name
        or any(ord(character) < 33 or ord(character) > 126 for character in name)
    ):
        _fail("INVALID_ZIPAPP_MEMBER_NAME")
    return pure


def _expected_zip_members(
    repository: Path, package: str, project_directory: str
) -> dict[str, bytes]:
    source = repository / project_directory / "src" / package
    try:
        root_metadata = source.lstat()
    except OSError as exc:
        raise SupplyChainError("UNSAFE_ZIPAPP_SOURCE") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        _fail("UNSAFE_ZIPAPP_SOURCE")
    python_files: list[Path] = []
    pending = [source]
    entry_count = 0
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise SupplyChainError("UNSAFE_ZIPAPP_SOURCE") from exc
        entry_count += len(entries)
        if entry_count > 512:
            _fail("UNSAFE_ZIPAPP_SOURCE")
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            path = Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode):
                if entry.name != "__pycache__":
                    pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if path.suffix == ".py":
                    python_files.append(path)
            else:
                _fail("UNSAFE_ZIPAPP_SOURCE")
    members = {
        "__main__.py": f"from {package}.main import main\nraise SystemExit(main())\n".encode(),
        "LICENSE": _read_source(repository / "LICENSE", maximum=128 * 1024),
    }
    for path in sorted(python_files):
        archive_name = (PurePosixPath(package) / path.relative_to(source)).as_posix()
        try:
            _validate_zip_member_name(archive_name)
        except SupplyChainError as exc:
            raise SupplyChainError("UNSAFE_ZIPAPP_SOURCE") from exc
        members[archive_name] = _read_source(path, maximum=MAX_BUNDLE_FILE_BYTES)
    return members


def _inspect_zipapp(
    path: Path,
    *,
    expected_members: Mapping[str, bytes],
) -> tuple[str, int, list[dict[str, Any]]]:
    payload = _read_source(path, maximum=MAX_ZIPAPP_BYTES)
    if not payload.startswith(b"#!/usr/bin/env python3\n"):
        _fail("INVALID_ZIPAPP_PREFIX")
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.comment:
                _fail("INVALID_ZIPAPP_METADATA")
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_MEMBERS:
                _fail("INVALID_ZIPAPP_MEMBERS")
            names = [info.filename for info in infos]
            if names != list(expected_members) or len(names) != len(set(names)):
                _fail("INVALID_ZIPAPP_MEMBERS")
            result: list[dict[str, Any]] = []
            for info in infos:
                try:
                    _validate_zip_member_name(info.filename)
                except SupplyChainError as exc:
                    raise SupplyChainError("INVALID_ZIPAPP_METADATA") from exc
                mode = info.external_attr >> 16
                if (
                    stat.S_IFMT(mode) != stat.S_IFREG
                    or stat.S_IMODE(mode) != 0o644
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.flag_bits & 1
                    or info.extra
                    or info.date_time != time.gmtime(SOURCE_DATE_EPOCH)[:6]
                    or info.file_size > MAX_BUNDLE_FILE_BYTES
                ):
                    _fail("INVALID_ZIPAPP_METADATA")
                member = archive.read(info)
                if len(member) != info.file_size or member != expected_members[info.filename]:
                    _fail("INVALID_ZIPAPP_MEMBER")
                result.append(
                    {
                        "mode": "0644",
                        "name": info.filename,
                        "sha256": _sha256(member),
                        "size": len(member),
                    }
                )
    except SupplyChainError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise SupplyChainError("INVALID_ZIPAPP") from exc
    return _sha256(payload), len(payload), result


def _zipapp_inventory(repository: Path) -> dict[str, Any]:
    roles = (
        ("bioprobe", "remote_probe", "bioprobe.pyz"),
        ("bioexec", "remote_executor", "bioexec.pyz"),
    )
    artifacts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="easy-pipe-zipapps-") as raw_temporary:
        temporary = Path(raw_temporary).resolve()
        build_home = temporary / "home"
        build_home.mkdir(mode=0o700)
        environment = {
            "HOME": str(build_home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
            "TMPDIR": str(temporary),
        }
        for package, project_directory, artifact_name in roles:
            builder = repository / project_directory / "build_zipapp.py"
            builder_payload = _read_source(builder, maximum=256 * 1024)
            expected = _expected_zip_members(repository, package, project_directory)
            outputs = [temporary / f"{package}-{index}.pyz" for index in (1, 2)]
            for output in outputs:
                _run_bounded(
                    [sys.executable, str(builder), "--output", str(output)],
                    cwd=repository,
                    environment=environment,
                    timeout=60,
                )
            first = _read_source(outputs[0], maximum=MAX_ZIPAPP_BYTES)
            second = _read_source(outputs[1], maximum=MAX_ZIPAPP_BYTES)
            if first != second:
                _fail("ZIPAPP_BUILD_NOT_REPRODUCIBLE")
            if builder_payload != _read_source(builder, maximum=256 * 1024) or expected != (
                _expected_zip_members(repository, package, project_directory)
            ):
                _fail("UNSTABLE_ZIPAPP_SOURCE")
            digest, size, members = _inspect_zipapp(outputs[0], expected_members=expected)
            artifacts.append(
                {
                    "archive_name": artifact_name,
                    "archive_sha256": digest,
                    "archive_size": size,
                    "build_count": 2,
                    "bytes_equal": True,
                    "members": members,
                    "role": package,
                    "version": _version_from_source(
                        repository / project_directory / "src" / package / "__init__.py"
                    ),
                }
            )
    return {
        "artifacts": artifacts,
        "format_version": FORMAT_VERSION,
        "native_remote_host_acceptance": {
            "reason": "local_reproducible_build_is_not_remote_host_acceptance",
            "status": "pending",
        },
        "source_date_epoch": SOURCE_DATE_EPOCH,
    }


def _container_inventory(repository: Path) -> dict[str, Any]:
    registry_path = repository / "src" / "biopipe" / "registry" / "data" / "fastq_qc.v1.yaml"
    registry_payload = _read_source(registry_path)
    try:
        registry = yaml.safe_load(registry_payload)
    except yaml.YAMLError as exc:
        raise SupplyChainError("INVALID_COMPONENT_REGISTRY") from exc
    if not isinstance(registry, dict) or not isinstance(registry.get("components"), list):
        _fail("INVALID_COMPONENT_REGISTRY")
    identities: dict[tuple[str, str], dict[str, Any]] = {}
    for component in registry["components"]:
        if not isinstance(component, dict):
            _fail("INVALID_COMPONENT_REGISTRY")
        tool = component.get("tool")
        container = component.get("container")
        if not isinstance(tool, dict) or not isinstance(container, dict):
            _fail("INVALID_COMPONENT_REGISTRY")
        component_id = _safe_record_text(
            component.get("component_id"), code="INVALID_COMPONENT_REGISTRY", maximum=128
        )
        name = _safe_record_text(tool.get("name"), code="INVALID_COMPONENT_REGISTRY", maximum=64)
        version = _safe_record_text(
            tool.get("version"), code="INVALID_COMPONENT_REGISTRY", maximum=64
        )
        license_value = _safe_record_text(
            tool.get("license"), code="INVALID_COMPONENT_REGISTRY", maximum=128
        )
        image = _safe_record_text(
            container.get("image"), code="INVALID_CONTAINER_IDENTITY", maximum=512
        )
        digest = _safe_record_text(
            container.get("digest"), code="INVALID_CONTAINER_IDENTITY", maximum=80
        )
        if (
            re.fullmatch(r"quay\.io/biocontainers/[a-z0-9_.-]+:[A-Za-z0-9_.-]+", image) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or SAFE_NAME.fullmatch(component_id) is None
            or SAFE_NAME.fullmatch(name) is None
        ):
            _fail("INVALID_CONTAINER_IDENTITY")
        key = (image, digest)
        existing = identities.get(key)
        facts = {"declared_component_license": license_value, "name": name, "version": version}
        if existing is None:
            identities[key] = {
                **facts,
                "component_ids": [component_id],
                "digest": digest,
                "digest_verification": {
                    "reason": "exact_image_not_fetched_or_inspected_by_this_generator",
                    "status": "pending",
                },
                "image": image,
                "license_review": {
                    "evidence_sha256": None,
                    "reviewed_at": None,
                    "reviewer": None,
                    "scope": "exact_container_contents",
                    "status": "pending",
                },
            }
        else:
            if any(existing[field] != value for field, value in facts.items()):
                _fail("CONFLICTING_CONTAINER_IDENTITY")
            existing["component_ids"].append(component_id)
    if len(identities) != 3 or {item["name"] for item in identities.values()} != {
        "fastp",
        "fastqc",
        "multiqc",
    }:
        _fail("CONTAINER_IDENTITY_SET_CHANGED")
    containers = sorted(identities.values(), key=lambda item: item["name"])
    for item in containers:
        item["component_ids"].sort()
    result = {
        "containers": containers,
        "format_version": FORMAT_VERSION,
        "registry": {
            "path": "src/biopipe/registry/data/fastq_qc.v1.yaml",
            "registry_schema_version": registry.get("registry_schema_version"),
            "registry_version": registry.get("registry_version"),
            "sha256": _sha256(registry_payload),
        },
        "release_readiness": {
            "reason": "digest_material_and_exact_image_license_reviews_are_pending",
            "status": "blocked",
        },
    }
    _validate_container_inventory(result)
    return result


def _validate_container_inventory(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"containers", "format_version", "registry", "release_readiness"}
        or value.get("format_version") != FORMAT_VERSION
        or value.get("release_readiness")
        != {
            "reason": "digest_material_and_exact_image_license_reviews_are_pending",
            "status": "blocked",
        }
        or not isinstance(value.get("registry"), dict)
        or set(value["registry"])
        != {"path", "registry_schema_version", "registry_version", "sha256"}
        or value["registry"].get("path") != "src/biopipe/registry/data/fastq_qc.v1.yaml"
        or value["registry"].get("registry_schema_version") != "1.0"
        or value["registry"].get("registry_version") != "1.0.0"
        or not isinstance(value["registry"].get("sha256"), str)
        or HEX64.fullmatch(value["registry"]["sha256"]) is None
        or not isinstance(value.get("containers"), list)
        or len(value["containers"]) != len(EXPECTED_CONTAINERS)
    ):
        _fail("INVALID_CONTAINER_INVENTORY")
    observed_names: list[str] = []
    for container in value["containers"]:
        if not isinstance(container, dict) or set(container) != {
            "component_ids",
            "declared_component_license",
            "digest",
            "digest_verification",
            "image",
            "license_review",
            "name",
            "version",
        }:
            _fail("INVALID_CONTAINER_INVENTORY")
        name = container.get("name")
        if not isinstance(name, str) or name not in EXPECTED_CONTAINERS:
            _fail("INVALID_CONTAINER_INVENTORY")
        observed_names.append(name)
        expected = EXPECTED_CONTAINERS[name]
        if any(container.get(field) != expected[field] for field in expected):
            _fail("INVALID_CONTAINER_INVENTORY")
        review = container.get("license_review")
        verification = container.get("digest_verification")
        if not isinstance(review, dict) or not isinstance(verification, dict):
            _fail("INVALID_CONTAINER_INVENTORY")
        if review.get("status") == "approved" or verification.get("status") == "verified":
            _fail("UNSUPPORTED_CONTAINER_APPROVAL")
        if review != {
            "evidence_sha256": None,
            "reviewed_at": None,
            "reviewer": None,
            "scope": "exact_container_contents",
            "status": "pending",
        } or verification != {
            "reason": "exact_image_not_fetched_or_inspected_by_this_generator",
            "status": "pending",
        }:
            _fail("INVALID_PENDING_CONTAINER_REVIEW")
    if observed_names != sorted(EXPECTED_CONTAINERS):
        _fail("INVALID_CONTAINER_INVENTORY")


README = b"""# Reproducible environment and supply-chain inventory

These files are generated create-only from `environments/m4-test.yml`,
`pyproject.toml`, the fixed component registry, and the two remote zipapp source
trees. Run `python scripts/generate_supply_chain_inventory.py verify` for a
fully offline integrity and contract check.

The explicit locks are cross-platform solver transactions, not proof that the
environments ran on native hosts. Native Linux and macOS runtime validation is
`pending` and belongs to release-acceptance CI. Container identities come from
the reviewed registry, but exact-image digest material verification and full
container-content license review are also `pending`; this directory does not
authorize a release or replace reviewer sign-off.

Generation uses only the public `conda-forge` and `bioconda` channels, fixed
virtual packages, an empty temporary solver root, and strict channel priority.
The output directory is published atomically and must not already exist.
"""


def _assert_no_private_data(payloads: Mapping[str, bytes], repository: Path | None = None) -> None:
    candidates = {
        str(Path.home()),
        socket.gethostname(),
        os.environ.get("USER", ""),
    }
    if repository is not None:
        candidates.update({str(repository.absolute()), str(repository.resolve())})
    tokens = [item.encode("utf-8") for item in candidates if len(item) >= 4]
    for payload in payloads.values():
        if any(token in payload for token in tokens):
            _fail("PRIVATE_DATA_IN_GENERATED_ARTIFACT")
        if any(marker in payload for marker in (b"/Users/", b"/home/", b"file://")):
            _fail("PRIVATE_DATA_IN_GENERATED_ARTIFACT")


def _publish_create_only(output_directory: Path, payloads: Mapping[str, bytes]) -> None:
    try:
        EvidenceBundleStore(output_directory).create(payloads)
    except Exception as exc:
        raise SupplyChainError("CREATE_ONLY_PUBLICATION_FAILED") from exc


def _reject_existing_output(output_directory: Path) -> None:
    try:
        output_directory.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SupplyChainError("CREATE_ONLY_PREFLIGHT_FAILED") from exc
    _fail("CREATE_ONLY_OUTPUT_EXISTS")


def generate(
    *,
    repository: Path,
    output_directory: Path,
    micromamba: Path,
) -> dict[str, Any]:
    repository = repository.absolute()
    _reject_existing_output(output_directory.absolute())
    direct_value, direct = _direct_dependencies(repository)
    source_sha256 = direct_value["sources"]["environment"]["sha256"]
    if not isinstance(source_sha256, str):
        _fail("INVALID_SOURCE_DIGEST")
    payloads: dict[str, bytes] = {
        "README.md": README,
        "containers.json": _json_bytes(_container_inventory(repository)),
        "direct-dependencies.json": _json_bytes(direct_value),
        "remote-zipapps.json": _json_bytes(_zipapp_inventory(repository)),
    }
    platform_summaries: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="easy-pipe-solver-identity-") as raw_temporary:
        temporary = Path(raw_temporary).resolve()
        environment = _controlled_environment(temporary, "osx-arm64")
        solver = _solver_identity(micromamba, temporary, environment)
    for platform in TARGETS:
        explicit, inventory, summary = _solve_platform(
            micromamba, repository, platform, direct, source_sha256
        )
        payloads[f"{platform}.explicit.txt"] = explicit
        payloads[f"{platform}.inventory.json"] = inventory
        platform_summaries.append(summary)
    metadata = {
        "channel_priority": "strict",
        "channels": [
            {"base_url": f"https://{CHANNEL_HOST}/{name}", "name": name} for name in CHANNELS
        ],
        "direct_dependencies": {
            "path": "environments/locks/direct-dependencies.json",
            "sha256": _sha256(payloads["direct-dependencies.json"]),
        },
        "format_version": FORMAT_VERSION,
        "platforms": platform_summaries,
        "resolution_scope": "cross_platform_metadata_only",
        "solver": solver,
        "source_environment": {
            "path": "environments/m4-test.yml",
            "sha256": source_sha256,
        },
    }
    payloads["lock-metadata.json"] = _json_bytes(metadata)
    payloads["SHA256SUMS"] = checksum_payloads(payloads)
    if frozenset(payloads) != OUTPUT_FILES:
        _fail("INTERNAL_OUTPUT_SET_MISMATCH")
    _assert_no_private_data(payloads, repository)
    _publish_create_only(output_directory, payloads)
    verification = verify(directory=output_directory, repository=repository)
    return {
        "file_count": len(payloads),
        "manifest_sha256": verification["manifest_sha256"],
        "native_runtime_validation": "pending",
        "status": "supply_chain_inventory_created_cross_platform",
    }


def _read_bundle(directory: Path) -> dict[str, bytes]:
    directory_descriptor: int | None = None
    try:
        directory_descriptor = EvidenceBundleStore._open_private_directory(directory.absolute())
        metadata = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail("UNSAFE_INVENTORY_DIRECTORY")
        names = os.listdir(directory_descriptor)
    except OSError as exc:
        raise SupplyChainError("UNSAFE_INVENTORY_DIRECTORY") from exc
    try:
        if set(names) != set(OUTPUT_FILES) or len(names) != len(OUTPUT_FILES):
            _fail("INVENTORY_FILE_SET_MISMATCH")
        payloads: dict[str, bytes] = {}
        for name in sorted(names):
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=directory_descriptor,
                )
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_mode & 0o022
                    or not 0 < before.st_size <= MAX_BUNDLE_FILE_BYTES
                ):
                    _fail("UNSAFE_INVENTORY_FILE")
                payload = bytearray()
                while chunk := os.read(
                    descriptor, min(1024 * 1024, MAX_BUNDLE_FILE_BYTES + 1 - len(payload))
                ):
                    payload.extend(chunk)
                    if len(payload) > MAX_BUNDLE_FILE_BYTES:
                        _fail("UNSAFE_INVENTORY_FILE")
                after = os.fstat(descriptor)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if len(payload) != before.st_size or any(
                    getattr(before, field) != getattr(after, field) for field in stable_fields
                ):
                    _fail("UNSTABLE_INVENTORY_FILE")
                payloads[name] = bytes(payload)
            except OSError as exc:
                raise SupplyChainError("UNSAFE_INVENTORY_FILE") from exc
            finally:
                if descriptor is not None:
                    with suppress(OSError):
                        os.close(descriptor)
        return payloads
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


def _parse_explicit(payload: bytes, *, platform: str) -> list[tuple[str, str]]:
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise SupplyChainError("INVALID_EXPLICIT_LOCK") from exc
    expected_header = [
        "# Generated create-only from environments/m4-test.yml; do not edit.",
        f"# target-platform: {platform}",
        "# native-runtime-validation: pending",
        "@EXPLICIT",
    ]
    if "\r" in text or not text.endswith("\n"):
        _fail("INVALID_EXPLICIT_LOCK")
    lines = text.splitlines()
    if lines[:4] != expected_header or len(lines) <= 4:
        _fail("INVALID_EXPLICIT_LOCK")
    result: list[tuple[str, str]] = []
    for line in lines[4:]:
        if line.count("#") != 1:
            _fail("INVALID_EXPLICIT_LOCK")
        url, digest = line.rsplit("#", 1)
        _validate_url(url, target_platform=platform)
        if HEX32.fullmatch(digest) is None:
            _fail("INVALID_EXPLICIT_LOCK")
        result.append((url, digest))
    if len(result) != len(set(result)):
        _fail("INVALID_EXPLICIT_LOCK")
    return result


def _verify_lock_pair(
    explicit: bytes,
    inventory: object,
    *,
    platform: str,
) -> int:
    if not isinstance(inventory, dict) or set(inventory) != {
        "direct_dependencies",
        "format_version",
        "native_runtime_validation",
        "packages",
        "resolution_status",
        "source_environment_sha256",
        "target_platform",
        "virtual_packages",
    }:
        _fail("INVALID_PACKAGE_INVENTORY")
    if (
        inventory.get("format_version") != FORMAT_VERSION
        or inventory.get("target_platform") != platform
        or inventory.get("resolution_status") != "resolved_cross_platform"
        or inventory.get("virtual_packages") != list(TARGETS[platform])
    ):
        _fail("INVALID_PACKAGE_INVENTORY")
    runtime = inventory.get("native_runtime_validation")
    direct = inventory.get("direct_dependencies")
    packages = inventory.get("packages")
    if (
        not isinstance(runtime, dict)
        or runtime
        != {
            "reason": "generated_by_cross_platform_metadata_solve_only",
            "status": "pending",
        }
        or not isinstance(direct, list)
    ):
        _fail("INVALID_PACKAGE_INVENTORY")
    normalized = _normalize_records(
        _inventory_to_solver_records(packages), target_platform=platform, direct=direct
    )
    if packages != normalized:
        _fail("NONCANONICAL_PACKAGE_INVENTORY")
    explicit_rows = _parse_explicit(explicit, platform=platform)
    inventory_rows = [(item["url"], item["md5"]) for item in normalized]
    if explicit_rows != inventory_rows:
        _fail("EXPLICIT_INVENTORY_MISMATCH")
    return len(normalized)


def _inventory_to_solver_records(packages: object) -> list[dict[str, Any]]:
    if not isinstance(packages, list):
        _fail("INVALID_PACKAGE_INVENTORY")
    result: list[dict[str, Any]] = []
    for item in packages:
        if not isinstance(item, dict):
            _fail("INVALID_PACKAGE_INVENTORY")
        result.append(
            {
                "build_number": item.get("build_number"),
                "build_string": item.get("build"),
                "channel": (f"https://{CHANNEL_HOST}/{item.get('channel')}/{item.get('subdir')}"),
                "depends": item.get("depends"),
                "fn": item.get("filename"),
                "license": item.get("license"),
                "md5": item.get("md5"),
                "name": item.get("name"),
                "sha256": item.get("sha256"),
                "size": item.get("size"),
                "subdir": item.get("subdir"),
                "timestamp": item.get("timestamp_ms"),
                "url": item.get("url"),
                "version": item.get("version"),
            }
        )
    return result


def _validate_direct_inventory(value: object) -> tuple[list[dict[str, str]], str]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "format_version",
            "project",
            "reference_environment",
            "remote_zipapps",
            "sources",
        }
        or value.get("format_version") != FORMAT_VERSION
    ):
        _fail("INVALID_DIRECT_DEPENDENCIES")
    sources = value.get("sources")
    environment = value.get("reference_environment")
    project = value.get("project")
    zipapps = value.get("remote_zipapps")
    if (
        not isinstance(sources, dict)
        or set(sources) != {"environment", "project"}
        or not isinstance(environment, dict)
        or set(environment) != {"channels", "direct", "name"}
        or not isinstance(project, dict)
        or set(project) != {"build", "development", "runtime"}
        or not isinstance(zipapps, dict)
        or set(zipapps) != {"dependency_model", "third_party_python_dependencies"}
        or environment.get("name") != "easy-pipe-m4"
        or environment.get("channels") != list(CHANNELS)
        or zipapps.get("third_party_python_dependencies") != []
        or zipapps.get("dependency_model") != "python-standard-library-only"
    ):
        _fail("INVALID_DIRECT_DEPENDENCIES")
    direct = environment.get("direct")
    if not isinstance(direct, list) or len(direct) != 20:
        _fail("INVALID_DIRECT_DEPENDENCIES")
    seen: set[str] = set()
    for item in direct:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "version"}
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("version"), str)
            or VERSION_ASSIGNMENT.fullmatch(f"{item['name']}={item['version']}") is None
            or item["name"] in seen
        ):
            _fail("INVALID_DIRECT_DEPENDENCIES")
        seen.add(item["name"])
    for group in ("build", "development", "runtime"):
        requirements = project.get(group)
        if not isinstance(requirements, list) or not requirements:
            _fail("INVALID_DIRECT_DEPENDENCIES")
        for requirement in requirements:
            _safe_requirement(requirement)
    environment_source = sources.get("environment")
    project_source = sources.get("project")
    if (
        not isinstance(environment_source, dict)
        or set(environment_source) != {"path", "sha256"}
        or environment_source.get("path") != "environments/m4-test.yml"
        or not isinstance(environment_source.get("sha256"), str)
        or HEX64.fullmatch(environment_source["sha256"]) is None
        or not isinstance(project_source, dict)
        or set(project_source) != {"path", "sha256"}
        or project_source.get("path") != "pyproject.toml"
        or not isinstance(project_source.get("sha256"), str)
        or HEX64.fullmatch(project_source["sha256"]) is None
    ):
        _fail("INVALID_DIRECT_DEPENDENCIES")
    return direct, environment_source["sha256"]


def _validate_zipapp_inventory(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "artifacts",
            "format_version",
            "native_remote_host_acceptance",
            "source_date_epoch",
        }
        or value.get("format_version") != FORMAT_VERSION
        or value.get("source_date_epoch") != SOURCE_DATE_EPOCH
        or value.get("native_remote_host_acceptance")
        != {
            "reason": "local_reproducible_build_is_not_remote_host_acceptance",
            "status": "pending",
        }
        or not isinstance(value.get("artifacts"), list)
        or len(value["artifacts"]) != 2
    ):
        _fail("INVALID_ZIPAPP_INVENTORY")
    expected_names = {"bioexec": "bioexec.pyz", "bioprobe": "bioprobe.pyz"}
    observed_roles: set[str] = set()
    for artifact in value["artifacts"]:
        if not isinstance(artifact, dict) or set(artifact) != {
            "archive_name",
            "archive_sha256",
            "archive_size",
            "build_count",
            "bytes_equal",
            "members",
            "role",
            "version",
        }:
            _fail("INVALID_ZIPAPP_INVENTORY")
        role = artifact.get("role")
        archive_sha256 = artifact.get("archive_sha256")
        archive_size = artifact.get("archive_size")
        version = artifact.get("version")
        members = artifact.get("members")
        if (
            not isinstance(role, str)
            or role not in expected_names
            or role in observed_roles
            or artifact.get("archive_name") != expected_names[role]
            or artifact.get("build_count") != 2
            or artifact.get("bytes_equal") is not True
            or not isinstance(archive_sha256, str)
            or HEX64.fullmatch(archive_sha256) is None
            or type(archive_size) is not int
            or not 0 < archive_size <= MAX_ZIPAPP_BYTES
            or not isinstance(version, str)
            or SAFE_VALUE.fullmatch(version) is None
            or not isinstance(members, list)
            or not 3 <= len(members) <= MAX_ZIP_MEMBERS
        ):
            _fail("INVALID_ZIPAPP_INVENTORY")
        observed_roles.add(role)
        names: list[str] = []
        total_member_size = 0
        for member in members:
            if not isinstance(member, dict) or set(member) != {"mode", "name", "sha256", "size"}:
                _fail("INVALID_ZIPAPP_INVENTORY")
            name = member.get("name")
            digest = member.get("sha256")
            size = member.get("size")
            if (
                not isinstance(name, str)
                or not isinstance(digest, str)
                or HEX64.fullmatch(digest) is None
                or member.get("mode") != "0644"
                or type(size) is not int
                or not 0 < size <= MAX_BUNDLE_FILE_BYTES
            ):
                _fail("INVALID_ZIPAPP_INVENTORY")
            try:
                _validate_zip_member_name(name)
            except SupplyChainError:
                _fail("INVALID_ZIPAPP_INVENTORY")
            names.append(name)
            total_member_size += size
        if (
            names[:2] != ["__main__.py", "LICENSE"]
            or len(names) != len(set(names))
            or names[2:] != sorted(names[2:])
            or any(
                not name.startswith(f"{role}/") or not name.endswith(".py") for name in names[2:]
            )
            or total_member_size >= archive_size
        ):
            _fail("INVALID_ZIPAPP_INVENTORY")
    if observed_roles != set(expected_names):
        _fail("INVALID_ZIPAPP_INVENTORY")


def verify(*, directory: Path, repository: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    payloads = _read_bundle(directory)
    if payloads["README.md"] != README:
        _fail("INVALID_SUPPLY_CHAIN_README")
    _assert_no_private_data(payloads)
    manifest_payload = payloads.pop("SHA256SUMS")
    try:
        expected = parse_checksum_manifest(manifest_payload, expected_names=frozenset(payloads))
    except ValueError as exc:
        raise SupplyChainError("INVALID_SUPPLY_CHAIN_CHECKSUMS") from exc
    observed = {name: _sha256(payload) for name, payload in payloads.items()}
    if expected != observed:
        _fail("SUPPLY_CHAIN_CHECKSUM_MISMATCH")
    parsed = {name: _load_json(payloads[name]) for name in JSON_FILES}
    direct = parsed["direct-dependencies.json"]
    direct_requirements, source_environment_sha256 = _validate_direct_inventory(direct)
    metadata = parsed["lock-metadata.json"]
    if (
        not isinstance(metadata, dict)
        or set(metadata)
        != {
            "channel_priority",
            "channels",
            "direct_dependencies",
            "format_version",
            "platforms",
            "resolution_scope",
            "solver",
            "source_environment",
        }
        or metadata.get("format_version") != FORMAT_VERSION
        or metadata.get("resolution_scope") != "cross_platform_metadata_only"
        or metadata.get("channel_priority") != "strict"
        or metadata.get("channels")
        != [{"base_url": f"https://{CHANNEL_HOST}/{name}", "name": name} for name in CHANNELS]
    ):
        _fail("INVALID_LOCK_METADATA")
    source_metadata = metadata.get("source_environment")
    direct_metadata = metadata.get("direct_dependencies")
    solver = metadata.get("solver")
    if (
        not isinstance(source_metadata, dict)
        or set(source_metadata) != {"path", "sha256"}
        or source_metadata.get("path") != "environments/m4-test.yml"
        or source_metadata.get("sha256") != source_environment_sha256
        or not isinstance(direct_metadata, dict)
        or set(direct_metadata) != {"path", "sha256"}
        or direct_metadata.get("path") != "environments/locks/direct-dependencies.json"
        or direct_metadata.get("sha256") != _sha256(payloads["direct-dependencies.json"])
        or not isinstance(solver, dict)
        or set(solver) != {"executable_sha256", "libmamba_version", "name", "version"}
        or solver.get("name") != "micromamba"
        or not isinstance(solver.get("version"), str)
        or SOLVER_VERSION.fullmatch(solver["version"]) is None
        or not isinstance(solver.get("libmamba_version"), str)
        or SOLVER_VERSION.fullmatch(solver["libmamba_version"]) is None
        or not isinstance(solver.get("executable_sha256"), str)
        or HEX64.fullmatch(solver["executable_sha256"]) is None
    ):
        _fail("INVALID_LOCK_METADATA")
    summaries = metadata.get("platforms")
    if (
        not isinstance(summaries, list)
        or len(summaries) != len(TARGETS)
        or [item.get("target_platform") for item in summaries if isinstance(item, dict)]
        != list(TARGETS)
    ):
        _fail("INVALID_LOCK_METADATA")
    counts: dict[str, int] = {}
    for platform in TARGETS:
        inventory = parsed[f"{platform}.inventory.json"]
        if isinstance(inventory, dict) and (
            inventory.get("direct_dependencies") != direct_requirements
            or inventory.get("source_environment_sha256") != source_environment_sha256
        ):
            _fail("DIRECT_DEPENDENCY_INVENTORY_MISMATCH")
        counts[platform] = _verify_lock_pair(
            payloads[f"{platform}.explicit.txt"], inventory, platform=platform
        )
        summary = next(
            (
                item
                for item in summaries
                if isinstance(item, dict) and item.get("target_platform") == platform
            ),
            None,
        )
        if (
            not isinstance(summary, dict)
            or set(summary)
            != {
                "explicit_lock",
                "inventory",
                "native_runtime_validation",
                "package_count",
                "resolution_status",
                "target_platform",
                "virtual_packages",
            }
            or not isinstance(summary.get("explicit_lock"), dict)
            or set(summary["explicit_lock"]) != {"path", "sha256"}
            or not isinstance(summary.get("inventory"), dict)
            or set(summary["inventory"]) != {"path", "sha256"}
            or summary.get("package_count") != counts[platform]
            or summary.get("native_runtime_validation") != "pending"
            or summary.get("resolution_status") != "resolved_cross_platform"
            or summary.get("virtual_packages") != list(TARGETS[platform])
            or summary.get("explicit_lock", {}).get("path")
            != f"environments/locks/{platform}.explicit.txt"
            or summary.get("explicit_lock", {}).get("sha256")
            != _sha256(payloads[f"{platform}.explicit.txt"])
            or summary.get("inventory", {}).get("path")
            != f"environments/locks/{platform}.inventory.json"
            or summary.get("inventory", {}).get("sha256")
            != _sha256(payloads[f"{platform}.inventory.json"])
        ):
            _fail("INVALID_LOCK_METADATA")
    _validate_container_inventory(parsed["containers.json"])
    _validate_zipapp_inventory(parsed["remote-zipapps.json"])
    repository = repository.absolute()
    expected_direct, _expected_pins = _direct_dependencies(repository)
    if direct != expected_direct:
        _fail("DIRECT_DEPENDENCY_SOURCE_MISMATCH")
    if parsed["containers.json"] != _container_inventory(repository):
        _fail("CONTAINER_SOURCE_INVENTORY_MISMATCH")
    if parsed["remote-zipapps.json"] != _zipapp_inventory(repository):
        _fail("ZIPAPP_SOURCE_INVENTORY_MISMATCH")
    return {
        "manifest_sha256": _sha256(manifest_payload),
        "package_counts": counts,
        "status": "supply_chain_inventory_verified_offline",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate_parser = subparsers.add_parser("generate", help="Solve and publish a new bundle.")
    generate_parser.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    generate_parser.add_argument(
        "--output", type=Path, default=REPOSITORY_ROOT / "environments" / "locks"
    )
    generate_parser.add_argument("--micromamba", type=Path)
    verify_parser = subparsers.add_parser("verify", help="Verify a committed bundle offline.")
    verify_parser.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    verify_parser.add_argument(
        "--directory", type=Path, default=REPOSITORY_ROOT / "environments" / "locks"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify":
            result = verify(directory=args.directory, repository=args.repository)
        else:
            selected = args.micromamba or Path(shutil.which("micromamba") or "")
            if not selected or not selected.is_absolute():
                _fail("MICROMAMBA_NOT_FOUND")
            result = generate(
                repository=args.repository,
                output_directory=args.output,
                micromamba=selected,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except SupplyChainError as error:
        print(
            json.dumps({"error": error.code, "status": "failed"}, sort_keys=True), file=sys.stderr
        )
        return 2
    except Exception:
        print(
            json.dumps(
                {"error": "INTERNAL_SUPPLY_CHAIN_ERROR", "status": "failed"}, sort_keys=True
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
