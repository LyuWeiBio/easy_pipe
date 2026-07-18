"""Create-only deployment of a bounded, production-only Nextflow bundle."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .config import AgentConfig
from .errors import AgentFailure, ReturnCode
from .paths import PathGuard, safe_relative_path
from .protocol import (
    require_exact_fields,
    require_identifier,
    require_int,
    require_sha256,
    require_string,
)
from .state import StateStore

_FIXED_FILES = frozenset(
    {
        "README.md",
        "assets/samplesheet.csv",
        "audit/events.jsonl",
        "conf/base.config",
        "conf/local.config",
        "dataset.manifest.resolved.json",
        "execution.plan.yaml",
        "main.nf",
        "nextflow.config",
        "pipeline.spec.yaml",
        "software.lock.yaml",
    }
)
_REQUIRED_FILES = frozenset(
    {
        "assets/samplesheet.csv",
        "conf/base.config",
        "conf/local.config",
        "dataset.manifest.resolved.json",
        "execution.plan.yaml",
        "main.nf",
        "modules/fastqc/raw.nf",
        "modules/multiqc/main.nf",
        "nextflow.config",
        "pipeline.spec.yaml",
        "software.lock.yaml",
    }
)
_MODULE_FILES = frozenset(
    {
        "modules/fastp/main.nf",
        "modules/fastqc/post_trim.nf",
        "modules/fastqc/raw.nf",
        "modules/multiqc/main.nf",
    }
)
_RAW_SUFFIXES = (
    ".fastq",
    ".fastq.gz",
    ".fq",
    ".fq.gz",
    ".bam",
    ".cram",
    ".sam",
    ".vcf",
    ".vcf.gz",
    ".bcl",
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


@dataclass(frozen=True)
class DeploymentFile:
    """One decoded and digest-checked deployment file."""

    path: str
    parts: tuple[str, ...]
    size: int
    sha256: str
    content: bytes


def deploy_bundle(
    payload: dict[str, Any],
    config: AgentConfig,
    state: StateStore,
) -> dict[str, Any]:
    """Validate and publish one immutable production bundle."""

    require_exact_fields(
        payload,
        required={
            "deployment_id",
            "preflight_id",
            "profile_id",
            "profile_hash",
            "project_hash",
            "bundle_hash",
            "deployment_dir",
            "files",
        },
    )
    deployment_id = require_identifier(payload["deployment_id"], "deployment_id")
    preflight_id = require_identifier(payload["preflight_id"], "preflight_id")
    profile_id = require_identifier(payload["profile_id"], "profile_id")
    profile_hash = require_sha256(payload["profile_hash"], "profile_hash")
    project_hash = require_sha256(payload["project_hash"], "project_hash")
    requested_bundle_hash = require_sha256(payload["bundle_hash"], "bundle_hash")
    if profile_id != config.profile_id or profile_hash != config.profile_hash:
        raise _deployment_failure("PROFILE_BINDING_MISMATCH")
    deployment_dir = _absolute_path(payload["deployment_dir"], "deployment_dir")
    authorized = PathGuard().authorize(deployment_dir, config.deploy_roots)
    if len(authorized.relative_parts) != 1:
        raise _schema("deployment_dir must be a direct child of a configured deploy root")
    files = _decode_files(payload["files"], config)
    metadata = [{"path": item.path, "sha256": item.sha256, "size": item.size} for item in files]
    bundle_hash = _canonical_hash(metadata)
    if bundle_hash != requested_bundle_hash:
        raise _deployment_failure("BUNDLE_HASH_MISMATCH")
    reservation = {
        "record_version": "1.0",
        "deployment_id": deployment_id,
        "preflight_id": preflight_id,
        "profile_id": profile_id,
        "profile_hash": profile_hash,
        "project_hash": project_hash,
        "bundle_hash": bundle_hash,
        "deployment_dir": deployment_dir,
        "files": metadata,
        "status": "reserved",
    }
    existing = _optional_deployment(state, deployment_id)
    if existing is not None:
        return _replay_deployment(existing, reservation, config)
    preflight = state.read("preflights", preflight_id)
    if (
        preflight.get("status") != "passed"
        or preflight.get("profile_id") != profile_id
        or preflight.get("profile_hash") != profile_hash
        or preflight.get("project_hash") != project_hash
        or preflight.get("deploy_dir") != deployment_dir
        or preflight.get("resume_run_id") is not None
        or preflight.get("consumed") is not False
        or not isinstance(preflight.get("expires_at"), int)
        or int(time.time()) > preflight["expires_at"]
    ):
        raise _deployment_failure("PREFLIGHT_BINDING_MISMATCH")
    try:
        state.create("deployments", deployment_id, reservation)
    except AgentFailure as failure:
        if failure.code != "STATE_ALREADY_EXISTS":
            raise
        return _replay_deployment(
            state.read("deployments", deployment_id),
            reservation,
            config,
        )
    try:
        device, inode = _publish_create_only(deployment_dir, files, config)
        complete = {
            **reservation,
            "directory_device": device,
            "directory_inode": inode,
            "status": "complete",
        }
        state.replace("deployments", deployment_id, complete)
    except AgentFailure:
        state.replace("deployments", deployment_id, {**reservation, "status": "failed"})
        raise
    except OSError as exc:
        state.replace("deployments", deployment_id, {**reservation, "status": "failed"})
        raise _deployment_failure("DEPLOYMENT_WRITE_FAILED") from exc
    return {
        "status": "deployed",
        "deployment_id": deployment_id,
        "bundle_hash": bundle_hash,
        "file_count": len(files),
    }


def _optional_deployment(state: StateStore, deployment_id: str) -> dict[str, Any] | None:
    try:
        return state.read("deployments", deployment_id)
    except AgentFailure as failure:
        if failure.code == "STATE_NOT_FOUND":
            return None
        raise


def _replay_deployment(
    existing: dict[str, Any],
    reservation: dict[str, Any],
    config: AgentConfig,
) -> dict[str, Any]:
    immutable_keys = set(reservation) - {"status"}
    if existing.get("status") != "complete" or any(
        existing.get(key) != reservation.get(key) for key in immutable_keys
    ):
        raise AgentFailure(
            ReturnCode.STATE_CONFLICT,
            "DEPLOYMENT_ID_CONFLICT",
            "deployment identifier is already bound to another or incomplete deployment",
        )
    verify_deployment(existing, config)
    files = existing.get("files")
    if not isinstance(files, list):
        raise _deployment_failure("DEPLOYMENT_RECORD_INVALID")
    return {
        "status": "deployed",
        "deployment_id": reservation["deployment_id"],
        "bundle_hash": reservation["bundle_hash"],
        "file_count": len(files),
    }


def verify_deployment(record: dict[str, Any], config: AgentConfig) -> None:
    """Re-open and completely inventory a deployment before every run."""

    if record.get("status") != "complete":
        raise _deployment_failure("DEPLOYMENT_INCOMPLETE")
    path = record.get("deployment_dir")
    metadata = record.get("files")
    if not isinstance(path, str) or not isinstance(metadata, list):
        raise _deployment_failure("DEPLOYMENT_RECORD_INVALID")
    expected: dict[str, tuple[int, str]] = {}
    for item in metadata:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise _deployment_failure("DEPLOYMENT_RECORD_INVALID")
        relative = item.get("path")
        size = item.get("size")
        digest = item.get("sha256")
        if (
            not isinstance(relative, str)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not isinstance(digest, str)
        ):
            raise _deployment_failure("DEPLOYMENT_RECORD_INVALID")
        expected[relative] = (size, digest)
    guard = PathGuard()
    with guard.open_directory(
        path,
        config.deploy_roots,
        require_trusted_owner=True,
        require_no_group_world_write=True,
    ) as (directory, _authorized):
        directory_stat = os.fstat(directory)
        if (
            directory_stat.st_dev != record.get("directory_device")
            or directory_stat.st_ino != record.get("directory_inode")
            or stat.S_IMODE(directory_stat.st_mode) != 0o500
        ):
            raise _deployment_failure("DEPLOYMENT_DIRECTORY_CHANGED")
        observed = _inventory(
            directory,
            expected,
            maximum_entries=config.limits.max_deployment_files * 4,
            maximum_file_bytes=config.limits.max_file_bytes,
            maximum_total_bytes=config.limits.max_deployment_bytes,
        )
    if set(observed) != set(expected):
        raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
    for relative, (observed_size, observed_digest) in observed.items():
        if expected[relative] != (observed_size, observed_digest):
            raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
    if _canonical_hash(
        [
            {"path": name, "sha256": digest, "size": size}
            for name, (size, digest) in sorted(observed.items())
        ]
    ) != record.get("bundle_hash"):
        raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")


def _decode_files(value: Any, config: AgentConfig) -> tuple[DeploymentFile, ...]:
    if not isinstance(value, list) or not value or len(value) > config.limits.max_deployment_files:
        raise _schema("files must be a bounded non-empty array")
    decoded: list[DeploymentFile] = []
    names: set[str] = set()
    total = 0
    for item in value:
        if not isinstance(item, dict):
            raise _schema("deployment file entries must be objects")
        require_exact_fields(
            item,
            required={"path", "size", "sha256", "content_base64"},
        )
        relative = require_string(item["path"], "file.path")
        parts = safe_relative_path(relative)
        if relative in names or not _is_production_file(relative):
            raise _deployment_failure("DEPLOYMENT_FILE_FORBIDDEN")
        if relative.casefold().endswith(_RAW_SUFFIXES):
            raise _deployment_failure("RAW_DATA_DEPLOYMENT_FORBIDDEN")
        names.add(relative)
        declared_size = require_int(item["size"], "file.size", 0, config.limits.max_file_bytes)
        declared_hash = require_sha256(item["sha256"], "file.sha256")
        encoded = require_string(
            item["content_base64"],
            "file.content_base64",
            maximum_bytes=((config.limits.max_file_bytes + 2) // 3) * 4 + 4,
        )
        try:
            content = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise _schema("file.content_base64 must be strict base64") from exc
        if base64.b64encode(content).decode("ascii") != encoded:
            raise _schema("file.content_base64 must use canonical padding")
        total += len(content)
        if len(content) != declared_size or hashlib.sha256(content).hexdigest() != declared_hash:
            raise _deployment_failure("DEPLOYMENT_FILE_DIGEST_MISMATCH")
        if total > config.limits.max_deployment_bytes:
            raise AgentFailure(
                ReturnCode.BUDGET_EXCEEDED,
                "DEPLOYMENT_BUDGET_EXCEEDED",
                "deployment exceeds the configured byte budget",
            )
        decoded.append(
            DeploymentFile(
                path=relative,
                parts=parts,
                size=declared_size,
                sha256=declared_hash,
                content=content,
            )
        )
    if not names >= _REQUIRED_FILES:
        raise _deployment_failure("DEPLOYMENT_INCOMPLETE")
    return tuple(sorted(decoded, key=lambda entry: entry.path))


def _is_production_file(relative: str) -> bool:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        return False
    if relative in _FIXED_FILES:
        return True
    return relative in _MODULE_FILES


def _publish_create_only(
    path: str,
    files: tuple[DeploymentFile, ...],
    config: AgentConfig,
) -> tuple[int, int]:
    guard = PathGuard()
    with guard.open_parent(
        path,
        config.deploy_roots,
        require_trusted_owner=True,
        require_no_group_world_write=True,
    ) as (parent, leaf, _authorized):
        try:
            os.mkdir(leaf, 0o700, dir_fd=parent)
        except FileExistsError as exc:
            raise AgentFailure(
                ReturnCode.STATE_CONFLICT,
                "TARGET_ALREADY_EXISTS",
                "a create-only deployment target already exists",
            ) from exc
        directory = os.open(leaf, _DIRECTORY_FLAGS, dir_fd=parent)
        try:
            metadata = os.fstat(directory)
            current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise _deployment_failure("DEPLOYMENT_DIRECTORY_CHANGED")
            for item in files:
                _write_relative(directory, item)
            _seal_directories(directory)
            os.fchmod(directory, 0o500)
            os.fsync(directory)
            os.fsync(parent)
            return metadata.st_dev, metadata.st_ino
        finally:
            os.close(directory)


def _write_relative(root: int, item: DeploymentFile) -> None:
    directory = os.dup(root)
    try:
        for part in item.parts[:-1]:
            with contextlib.suppress(FileExistsError):
                os.mkdir(part, 0o700, dir_fd=directory)
            next_directory = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory)
            current = os.stat(part, dir_fd=directory, follow_symlinks=False)
            opened = os.fstat(next_directory)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                os.close(next_directory)
                raise _deployment_failure("UNSAFE_DEPLOYMENT_DIRECTORY")
            os.close(directory)
            directory = next_directory
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(item.parts[-1], flags, 0o600, dir_fd=directory)
        try:
            _write_all(descriptor, item.content)
            created = os.fstat(descriptor)
            if not stat.S_ISREG(created.st_mode) or created.st_size != item.size:
                raise _deployment_failure("DEPLOYMENT_WRITE_FAILED")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)


def _inventory(
    root: int,
    expected: dict[str, tuple[int, str]],
    *,
    maximum_entries: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    entries_seen = 0
    total_bytes = 0

    def visit(directory: int, prefix: tuple[str, ...]) -> None:
        nonlocal entries_seen, total_bytes
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name
                entries_seen += 1
                if entries_seen > maximum_entries:
                    raise AgentFailure(
                        ReturnCode.BUDGET_EXCEEDED,
                        "DEPLOYMENT_INVENTORY_BUDGET_EXCEEDED",
                        "deployment inventory exceeds its configured budget",
                    )
                if name in {".", ".."}:
                    raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                relative = "/".join((*prefix, name))
                if stat.S_ISLNK(current.st_mode):
                    raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                if stat.S_ISDIR(current.st_mode):
                    if stat.S_IMODE(current.st_mode) != 0o500:
                        raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                    prefix_text = f"{relative}/"
                    if not any(item.startswith(prefix_text) for item in expected):
                        raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory)
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (
                            current.st_dev,
                            current.st_ino,
                        ):
                            raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                        visit(child, (*prefix, name))
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(current.st_mode):
                    raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                if stat.S_IMODE(current.st_mode) != 0o400:
                    raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                if relative not in expected or current.st_size > maximum_file_bytes:
                    raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                if current.st_size != expected[relative][0]:
                    raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                total_bytes += current.st_size
                if total_bytes > maximum_total_bytes:
                    raise AgentFailure(
                        ReturnCode.BUDGET_EXCEEDED,
                        "DEPLOYMENT_INVENTORY_BUDGET_EXCEEDED",
                        "deployment inventory exceeds its configured byte budget",
                    )
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory,
                )
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino) != (
                        current.st_dev,
                        current.st_ino,
                    ):
                        raise _deployment_failure("DEPLOYMENT_CONTENT_CHANGED")
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                finally:
                    os.close(descriptor)
                result[relative] = (size, digest.hexdigest())

    visit(root, ())
    return result


def _seal_directories(root: int) -> None:
    with os.scandir(root) as entries:
        for entry in entries:
            current = os.stat(entry.name, dir_fd=root, follow_symlinks=False)
            if stat.S_ISREG(current.st_mode):
                if stat.S_IMODE(current.st_mode) != 0o400:
                    raise _deployment_failure("DEPLOYMENT_WRITE_FAILED")
                continue
            if not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode):
                raise _deployment_failure("DEPLOYMENT_WRITE_FAILED")
            child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=root)
            try:
                _seal_directories(child)
                os.fchmod(child, 0o500)
                os.fsync(child)
            finally:
                os.close(child)


def _canonical_hash(value: Any) -> str:
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _absolute_path(value: Any, field: str) -> str:
    text = require_string(value, field)
    path = PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts or str(path) != text or text == "/":
        raise _schema(f"{field} must be a normalized non-root absolute POSIX path")
    return text


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written < 1:
            raise OSError("deployment write made no progress")
        remaining = remaining[written:]


def _schema(message: str) -> AgentFailure:
    return AgentFailure(ReturnCode.PROTOCOL_ERROR, "SCHEMA_ERROR", message)


def _deployment_failure(code: str) -> AgentFailure:
    return AgentFailure(
        ReturnCode.DEPLOYMENT_FAILED,
        code,
        "the production deployment was rejected",
        remediation=["Rebuild a reviewed production bundle and deploy to a new directory."],
    )


__all__ = ["deploy_bundle", "verify_deployment"]
