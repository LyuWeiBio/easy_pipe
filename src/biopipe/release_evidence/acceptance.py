"""Create and verify bounded CI-only release-acceptance evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final, cast

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.probe.bounded import run_bounded
from biopipe.release_evidence.checksums import (
    ARTIFACT_LOGICAL_NAMES,
    checksum_payloads,
    hash_release_artifact,
    parse_checksum_manifest,
    read_bounded_regular,
    render_checksum_manifest,
)
from biopipe.release_evidence.generator import (
    release_git_environment,
    resolve_clean_repository_commit,
    validate_runtime_repository_binding,
)
from biopipe.release_evidence.store import EvidenceBundleStore
from biopipe.version import CONTROLLER_VERSION

ACCEPTANCE_EVIDENCE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "SHA256SUMS",
        "acceptance-summary.json",
        "environment-explicit.txt",
        "remote-artifacts.sha256",
        "source-artifacts.sha256",
        "test-summary.txt",
    }
)
_CORE_NAMES: Final[frozenset[str]] = ACCEPTANCE_EVIDENCE_NAMES - {"SHA256SUMS"}
_PLATFORMS: Final[frozenset[str]] = frozenset({"linux-64", "osx-arm64"})
_CHANNELS: Final[frozenset[str]] = frozenset({"bioconda", "conda-forge"})
_RELEASE_ID = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-rc[1-9][0-9]*$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CI_RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_MD5 = re.compile(r"^[0-9a-f]{32}$")
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_.+-]+\.(?:conda|tar\.bz2)$")
_MAX_INPUT_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 8 * 1024 * 1024
_CHECKS: Final[dict[str, str]] = {
    "anonymous_release_acceptance": "passed",
    "clean_sdist_install": "passed",
    "clean_wheel_install": "passed",
    "locked_native_environment": "passed",
    "nextflow_offline_policy": "passed",
    "required_tool_tests_without_skips": "passed",
    "zipapp_reproducibility": "passed",
}
_RUNTIME_VERSIONS: Final[dict[str, str]] = {
    "fastp": "1.3.6",
    "fastqc": "0.12.1",
    "java": "23.0.2",
    "multiqc": "1.35",
    "nextflow": "26.04.6",
    "nf-test": "0.9.5",
    "python": "3.12.11",
}
_TEST_RESULT: Final[dict[str, object]] = {
    "errors": 0,
    "failures": 0,
    "skipped": 0,
    "status": "passed",
    "tests": 3,
}


@dataclass(frozen=True, slots=True)
class AcceptanceArtifactPaths:
    """Fixed artifact roles used by the release-acceptance workflow."""

    wheel: Path
    sdist: Path
    bioprobe_first: Path
    bioprobe_second: Path
    bioexec_first: Path
    bioexec_second: Path


def verify_native_environment_export(
    *,
    repository: str | Path,
    environment_export: str | Path,
    platform: str,
) -> dict[str, object]:
    """Bind one native explicit export to the reviewed platform lock."""

    repository_path = Path(repository).absolute()
    commit = _resolve_acceptance_commit(repository_path)
    export_payload = read_bounded_regular(
        environment_export,
        role=f"{platform}_native_export",
        limit_bytes=_MAX_INPUT_BYTES,
    )
    result = _verify_native_export_payload(
        repository=repository_path,
        commit=commit,
        export_payload=export_payload,
        platform=platform,
    )
    if _resolve_acceptance_commit(repository_path) != commit:
        raise _validation_error("candidate repository changed during native lock verification")
    return {**result, "source_git_commit": commit}


def _verify_native_export_payload(
    *,
    repository: Path,
    commit: str,
    export_payload: bytes,
    platform: str,
) -> dict[str, object]:
    if platform not in _PLATFORMS:
        raise _validation_error("unsupported native environment platform")
    lock_payload = _read_committed_lock(repository, commit=commit, platform=platform)
    lock_rows = _parse_explicit(lock_payload, platform=platform)
    export_rows = _parse_explicit(export_payload, platform=platform)
    if export_rows != lock_rows:
        raise _validation_error("native environment export does not match the reviewed lock")
    return {
        "lock_sha256": hashlib.sha256(lock_payload).hexdigest(),
        "package_count": len(lock_rows),
        "status": "verified_against_committed_lock",
        "target_platform": platform,
    }


def create_release_acceptance_evidence(
    *,
    repository: str | Path,
    output_directory: str | Path,
    release_id: str,
    created_at: str,
    ci_run_id: str,
    environment_export: str | Path,
    test_result: str | Path,
    artifact_paths: AcceptanceArtifactPaths,
) -> dict[str, object]:
    """Create one sealed, explicitly unreviewed Linux CI evidence bundle."""

    _validate_identity(
        release_id,
        created_at,
        ci_run_id,
        controller_version=CONTROLLER_VERSION,
    )
    repository_path = Path(repository).absolute()
    commit = _resolve_acceptance_commit(repository_path)
    validate_runtime_repository_binding(repository_path, commit)
    raw_environment_export = read_bounded_regular(
        environment_export,
        role="linux_native_environment_export",
        limit_bytes=_MAX_INPUT_BYTES,
    )
    native = _verify_native_export_payload(
        repository=repository_path,
        commit=commit,
        export_payload=raw_environment_export,
        platform="linux-64",
    )
    result = _load_test_result(test_result)
    if result != _TEST_RESULT:
        raise _validation_error("release acceptance did not pass all tests without skips")

    artifact_hashes = _artifact_hashes(artifact_paths)
    export_payload = _render_native_export(raw_environment_export, platform="linux-64")
    summary = {
        "acceptance_format_version": "1.0",
        "acceptance_status": "passed",
        "artifacts": artifact_hashes,
        "checks": _CHECKS,
        "ci_run_id": ci_run_id,
        "controller_version": CONTROLLER_VERSION,
        "created_at": created_at,
        "data_classification": "anonymous_synthetic_only",
        "environment_export_sha256": hashlib.sha256(export_payload).hexdigest(),
        "environment_lock_sha256": native["lock_sha256"],
        "environment_package_count": native["package_count"],
        "evidence_status": "CI_GENERATED_UNREVIEWED",
        "independent_review_status": "pending",
        "network_claim": "nextflow_offline_policy_enforced_not_network_isolation",
        "real_container_runtime_exercised": False,
        "real_remote_host_exercised": False,
        "real_ssh_exercised": False,
        "release_decision": "BLOCKED",
        "release_id": release_id,
        "required_runtime_versions": _RUNTIME_VERSIONS,
        "source_git_commit": commit,
        "synthetic_local_only": True,
        "target_platform": "linux-64",
        "test_counts": result,
    }
    payloads = {
        "acceptance-summary.json": _render_json(summary),
        "environment-explicit.txt": export_payload,
        "remote-artifacts.sha256": render_checksum_manifest(
            {
                ARTIFACT_LOGICAL_NAMES["bioexec"]: artifact_hashes["bioexec_sha256"],
                ARTIFACT_LOGICAL_NAMES["bioprobe"]: artifact_hashes["bioprobe_sha256"],
            }
        ),
        "source-artifacts.sha256": render_checksum_manifest(
            {
                ARTIFACT_LOGICAL_NAMES["sdist"]: artifact_hashes["sdist_sha256"],
                ARTIFACT_LOGICAL_NAMES["wheel"]: artifact_hashes["wheel_sha256"],
            }
        ),
        "test-summary.txt": _render_test_summary(summary),
    }
    _validate_core_payloads(payloads)
    _assert_sanitized(payloads)
    payloads["SHA256SUMS"] = checksum_payloads(payloads)
    if _resolve_acceptance_commit(repository_path) != commit:
        raise _validation_error("candidate repository changed during evidence collection")
    EvidenceBundleStore(output_directory).create(payloads)
    verification = verify_release_acceptance_evidence(output_directory)
    return {
        **verification,
        "status": "release_acceptance_evidence_created_unreviewed",
    }


def verify_release_acceptance_evidence(directory: str | Path) -> dict[str, object]:
    """Verify one CI evidence bundle without repository or network access."""

    payloads = _read_acceptance_directory(Path(directory).absolute())
    core = {name: payload for name, payload in payloads.items() if name != "SHA256SUMS"}
    _validate_core_payloads(core)
    _assert_sanitized(core)
    try:
        expected = parse_checksum_manifest(
            payloads["SHA256SUMS"],
            expected_names=_CORE_NAMES,
        )
    except ValueError as exc:
        raise _validation_error("release acceptance checksum manifest is invalid") from exc
    observed_hashes = {
        name: hashlib.sha256(payload).hexdigest() for name, payload in sorted(core.items())
    }
    if expected != observed_hashes:
        raise _validation_error("release acceptance bundle checksum does not match")
    summary = _decode_json(core["acceptance-summary.json"], role="acceptance_summary")
    return {
        "acceptance_status": "passed",
        "evidence_manifest_sha256": hashlib.sha256(payloads["SHA256SUMS"]).hexdigest(),
        "file_count": len(payloads),
        "release_decision": "BLOCKED",
        "release_id": summary["release_id"],
        "source_git_commit": summary["source_git_commit"],
        "status": "release_acceptance_evidence_verified_offline",
    }


def _artifact_hashes(paths: AcceptanceArtifactPaths) -> dict[str, str]:
    first_probe = hash_release_artifact(paths.bioprobe_first, "bioprobe")
    second_probe = hash_release_artifact(paths.bioprobe_second, "bioprobe")
    first_executor = hash_release_artifact(paths.bioexec_first, "bioexec")
    second_executor = hash_release_artifact(paths.bioexec_second, "bioexec")
    if first_probe != second_probe or first_executor != second_executor:
        raise _validation_error("remote zipapp double builds are not byte-identical")
    return {
        "bioexec_sha256": first_executor,
        "bioprobe_sha256": first_probe,
        "sdist_sha256": hash_release_artifact(paths.sdist, "sdist"),
        "wheel_sha256": hash_release_artifact(paths.wheel, "wheel"),
    }


def _resolve_acceptance_commit(repository: Path) -> str:
    return resolve_clean_repository_commit(
        repository,
        require_no_ignored_untracked=True,
    )


def _read_committed_lock(repository: Path, *, commit: str, platform: str) -> bytes:
    relative = f"environments/locks/{platform}.explicit.txt"
    try:
        result = run_bounded(
            (
                "git",
                "--no-replace-objects",
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.bare=false",
                "-c",
                f"core.worktree={os.fspath(repository)}",
                "-c",
                "core.sparseCheckout=false",
                "-c",
                "core.sparseCheckoutCone=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.trustctime=true",
                "-c",
                "core.checkStat=default",
                "-c",
                "core.fileMode=true",
                "-c",
                "core.symlinks=true",
                "-c",
                f"core.excludesFile={os.devnull}",
                "-C",
                os.fspath(repository),
                "show",
                f"{commit}:{relative}",
            ),
            input_text="",
            timeout=10.0,
            stdout_limit=_MAX_INPUT_BYTES,
            stderr_limit=1,
            env=release_git_environment(),
        )
        payload = result.stdout.encode("ascii")
    except (OSError, UnicodeError, subprocess.TimeoutExpired, ValueError) as exc:
        raise _validation_error("committed native environment lock is unavailable") from exc
    if result.returncode != 0 or not 0 < len(payload) <= _MAX_INPUT_BYTES:
        raise _validation_error("committed native environment lock is unavailable")
    return payload


def _open_directory_no_symlink(directory: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(directory)))
    parts = absolute.parts
    if (
        not parts
        or not absolute.is_absolute()
        or any(component in {"", ".", ".."} for component in parts[1:])
    ):
        raise OSError("acceptance evidence directory path is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(parts[0], flags)
    try:
        for component in parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("acceptance evidence root is not a directory")
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_acceptance_directory(root: Path) -> dict[str, bytes]:
    descriptor: int | None = None
    try:
        descriptor = _open_directory_no_symlink(root)
        if frozenset(os.listdir(descriptor)) != ACCEPTANCE_EVIDENCE_NAMES:
            raise OSError("acceptance evidence file set mismatch")
        payloads: dict[str, bytes] = {}
        total = 0
        for name in sorted(ACCEPTANCE_EVIDENCE_NAMES):
            file_descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=descriptor,
            )
            try:
                before = os.fstat(file_descriptor)
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_INPUT_BYTES:
                    raise OSError("unsafe acceptance evidence file")
                payload = bytearray()
                while chunk := os.read(
                    file_descriptor,
                    min(1024 * 1024, _MAX_INPUT_BYTES + 1 - len(payload)),
                ):
                    payload.extend(chunk)
                    if len(payload) > _MAX_INPUT_BYTES:
                        raise OSError("acceptance evidence file exceeds its bound")
                after = os.fstat(file_descriptor)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if len(payload) != before.st_size or any(
                    getattr(before, field) != getattr(after, field) for field in stable_fields
                ):
                    raise OSError("acceptance evidence file changed while reading")
                payloads[name] = bytes(payload)
                total += len(payload)
            finally:
                os.close(file_descriptor)
        if (
            total > _MAX_BUNDLE_BYTES
            or frozenset(os.listdir(descriptor)) != ACCEPTANCE_EVIDENCE_NAMES
        ):
            raise OSError("acceptance evidence directory changed while reading")
        return payloads
    except (OSError, ValueError) as exc:
        raise _read_error() from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _parse_explicit(payload: bytes, *, platform: str) -> dict[str, str]:
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise _validation_error("explicit environment export is not ASCII") from exc
    if not text or "\r" in text or not text.endswith("\n"):
        raise _validation_error("explicit environment export has invalid newlines")
    lines = text.splitlines()
    if lines.count("@EXPLICIT") != 1:
        raise _validation_error("explicit environment export marker is invalid")
    marker = lines.index("@EXPLICIT")
    if any(not line.startswith("#") for line in lines[:marker]):
        raise _validation_error("explicit environment export header is invalid")
    rows: dict[str, str] = {}
    for line in lines[marker + 1 :]:
        if not line or line.startswith("#") or len(line) > 2048:
            raise _validation_error("explicit environment export row is invalid")
        url, separator, digest = line.rpartition("#")
        if separator != "#" or _MD5.fullmatch(digest) is None:
            raise _validation_error("explicit environment export digest is invalid")
        parsed = urllib.parse.urlsplit(url)
        path_parts = parsed.path.split("/")
        if (
            parsed.scheme != "https"
            or parsed.netloc != "conda.anaconda.org"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(path_parts) != 4
            or path_parts[0] != ""
            or path_parts[1] not in _CHANNELS
            or path_parts[2] not in {platform, "noarch"}
            or _PACKAGE_NAME.fullmatch(path_parts[3]) is None
            or urllib.parse.unquote(parsed.path) != parsed.path
            or url in rows
        ):
            raise _validation_error("explicit environment export URL is invalid")
        rows[url] = digest
    if not rows:
        raise _validation_error("explicit environment export contains no packages")
    return rows


def _render_native_export(payload: bytes, *, platform: str) -> bytes:
    rows = _parse_explicit(payload, platform=platform)
    lines = [
        "# Native release-acceptance CI export; candidate identity is in acceptance-summary.json.",
        f"# target-platform: {platform}",
        "@EXPLICIT",
        *(f"{url}#{rows[url]}" for url in sorted(rows)),
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def _load_test_result(path: str | Path) -> dict[str, object]:
    payload = read_bounded_regular(
        path,
        role="release_acceptance_test_result",
        limit_bytes=64 * 1024,
    )
    value = _decode_json(payload, role="release_acceptance_test_result")
    if not _is_exact_test_result(value):
        raise _validation_error("release acceptance test result has an invalid schema")
    return value


def _is_exact_test_result(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == set(_TEST_RESULT)
        and all(
            type(value[name]) is type(expected) and value[name] == expected
            for name, expected in _TEST_RESULT.items()
        )
    )


def _validate_core_payloads(payloads: Mapping[str, bytes]) -> None:
    if frozenset(payloads) != _CORE_NAMES:
        raise _validation_error("release acceptance evidence file set is incomplete")
    summary = _decode_json(payloads["acceptance-summary.json"], role="acceptance_summary")
    expected_keys = {
        "acceptance_format_version",
        "acceptance_status",
        "artifacts",
        "checks",
        "ci_run_id",
        "controller_version",
        "created_at",
        "data_classification",
        "environment_export_sha256",
        "environment_lock_sha256",
        "environment_package_count",
        "evidence_status",
        "independent_review_status",
        "network_claim",
        "real_container_runtime_exercised",
        "real_remote_host_exercised",
        "real_ssh_exercised",
        "release_decision",
        "release_id",
        "required_runtime_versions",
        "source_git_commit",
        "synthetic_local_only",
        "target_platform",
        "test_counts",
    }
    artifacts = summary.get("artifacts")
    if (
        set(summary) != expected_keys
        or summary.get("acceptance_format_version") != "1.0"
        or summary.get("acceptance_status") != "passed"
        or summary.get("checks") != _CHECKS
        or not isinstance(summary.get("controller_version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", summary["controller_version"]) is None
        or summary.get("data_classification") != "anonymous_synthetic_only"
        or summary.get("evidence_status") != "CI_GENERATED_UNREVIEWED"
        or summary.get("independent_review_status") != "pending"
        or summary.get("network_claim") != "nextflow_offline_policy_enforced_not_network_isolation"
        or summary.get("real_container_runtime_exercised") is not False
        or summary.get("real_remote_host_exercised") is not False
        or summary.get("real_ssh_exercised") is not False
        or summary.get("release_decision") != "BLOCKED"
        or summary.get("required_runtime_versions") != _RUNTIME_VERSIONS
        or summary.get("synthetic_local_only") is not True
        or summary.get("target_platform") != "linux-64"
        or not _is_exact_test_result(summary.get("test_counts"))
        or type(summary.get("environment_package_count")) is not int
        or not 1 <= summary["environment_package_count"] <= 1000
        or not isinstance(summary.get("environment_export_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", summary["environment_export_sha256"]) is None
        or not isinstance(summary.get("environment_lock_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", summary["environment_lock_sha256"]) is None
        or not isinstance(artifacts, dict)
        or set(artifacts) != {"bioexec_sha256", "bioprobe_sha256", "sdist_sha256", "wheel_sha256"}
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in artifacts.values()
        )
    ):
        raise _validation_error("release acceptance summary is invalid")
    release_id = summary.get("release_id")
    commit = summary.get("source_git_commit")
    created_at = summary.get("created_at")
    ci_run_id = summary.get("ci_run_id")
    if not all(isinstance(item, str) for item in (release_id, commit, created_at, ci_run_id)):
        raise _validation_error("release acceptance identity is invalid")
    _validate_identity(
        cast(str, release_id),
        cast(str, created_at),
        cast(str, ci_run_id),
        commit=cast(str, commit),
        controller_version=cast(str, summary["controller_version"]),
    )
    if (
        hashlib.sha256(payloads["environment-explicit.txt"]).hexdigest()
        != summary["environment_export_sha256"]
    ):
        raise _validation_error("environment export is not bound to the acceptance summary")
    rows = _parse_explicit(payloads["environment-explicit.txt"], platform="linux-64")
    if len(rows) != summary["environment_package_count"]:
        raise _validation_error("environment package count is inconsistent")
    try:
        source = parse_checksum_manifest(
            payloads["source-artifacts.sha256"],
            expected_names=frozenset(
                {ARTIFACT_LOGICAL_NAMES["sdist"], ARTIFACT_LOGICAL_NAMES["wheel"]}
            ),
        )
        remote = parse_checksum_manifest(
            payloads["remote-artifacts.sha256"],
            expected_names=frozenset(
                {ARTIFACT_LOGICAL_NAMES["bioexec"], ARTIFACT_LOGICAL_NAMES["bioprobe"]}
            ),
        )
    except ValueError as exc:
        raise _validation_error("release artifact checksum evidence is invalid") from exc
    if source != {
        ARTIFACT_LOGICAL_NAMES["sdist"]: artifacts["sdist_sha256"],
        ARTIFACT_LOGICAL_NAMES["wheel"]: artifacts["wheel_sha256"],
    } or remote != {
        ARTIFACT_LOGICAL_NAMES["bioexec"]: artifacts["bioexec_sha256"],
        ARTIFACT_LOGICAL_NAMES["bioprobe"]: artifacts["bioprobe_sha256"],
    }:
        raise _validation_error("artifact hashes are not bound to the acceptance summary")
    if payloads["test-summary.txt"] != _render_test_summary(summary):
        raise _validation_error("release acceptance test summary is not canonical")


def _render_test_summary(summary: Mapping[str, Any]) -> bytes:
    counts = cast(Mapping[str, object], summary["test_counts"])
    lines = [
        "release-acceptance-ci-format: 1",
        f"release-id: {summary['release_id']}",
        f"source-git-commit: {summary['source_git_commit']}",
        f"ci-run-id: {summary['ci_run_id']}",
        "target-platform: linux-64",
        "BIOPIPE_REQUIRE_REAL_TOOLS: 1",
        "NXF_OFFLINE: true",
        f"tests: {counts['tests']}",
        f"failures: {counts['failures']}",
        f"errors: {counts['errors']}",
        f"skipped: {counts['skipped']}",
        "release-decision: BLOCKED",
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def _validate_identity(
    release_id: str,
    created_at: str,
    ci_run_id: str,
    *,
    commit: str | None = None,
    controller_version: str,
) -> None:
    try:
        parsed = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise _validation_error("release acceptance creation time is invalid") from exc
    if (
        _RELEASE_ID.fullmatch(release_id) is None
        or release_id.rsplit("-rc", maxsplit=1)[0] != controller_version
        or _CI_RUN_ID.fullmatch(ci_run_id) is None
        or parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != created_at
        or (commit is not None and _COMMIT.fullmatch(commit) is None)
    ):
        raise _validation_error("release acceptance identity is invalid")


def _decode_json(payload: bytes, *, role: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise _validation_error(f"{role} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise _validation_error(f"{role} JSON must be an object")
    return cast(dict[str, Any], value)


def _render_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _assert_sanitized(payloads: Mapping[str, bytes]) -> None:
    forbidden = (
        b"/Users/",
        b"/home/",
        b"file://",
        b"PRIVATE KEY",
        b"Authorization:",
        b"Bearer ",
        b"approval.key",
        b".fastq",
        b".fq",
    )
    if any(marker in payload for payload in payloads.values() for marker in forbidden):
        raise _validation_error("release acceptance evidence contains forbidden material")


def _read_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.ARTIFACT_READ_FAILED,
        "Release acceptance evidence is missing, unsafe, or incomplete.",
        remediation=["Use the exact create-only CI acceptance evidence bundle."],
    )


def _validation_error(reason: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "Release acceptance evidence did not satisfy the reviewed format.",
        context={"reason": reason},
        remediation=["Re-run the release-acceptance workflow from the exact candidate."],
    )


__all__ = [
    "ACCEPTANCE_EVIDENCE_NAMES",
    "AcceptanceArtifactPaths",
    "create_release_acceptance_evidence",
    "verify_native_environment_export",
    "verify_release_acceptance_evidence",
]
