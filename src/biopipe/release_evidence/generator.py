"""Create and verify bounded, offline-reviewable release evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Final, cast

from pydantic import ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.probe.bounded import run_bounded
from biopipe.registry import RegistryValidationError, load_default_registry
from biopipe.release_evidence.checksums import (
    ARTIFACT_LOGICAL_NAMES,
    checksum_payloads,
    hash_release_artifact,
    parse_checksum_manifest,
    read_bounded_regular,
    render_checksum_manifest,
)
from biopipe.release_evidence.models import EvidenceVerification, ReleaseCandidate
from biopipe.release_evidence.store import EvidenceBundleStore
from biopipe.version import (
    CLI_CONTRACT_VERSION,
    COMPILER_VERSION,
    CONTROLLER_VERSION,
    MVP_SCHEMA_VERSION,
    PROBE_VERSION,
    REGISTRY_VERSION,
    REMOTE_EXECUTOR_VERSION,
)

EVIDENCE_MANIFEST_NAME: Final[str] = "SHA256SUMS"
_MAX_RESOURCE_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 16 * 1024 * 1024
_GIT_TIMEOUT_SECONDS: Final[float] = 10.0
_RUNTIME_REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_TEMPLATE_DIRECTORY: Final[Path] = Path("release-evidence/template")
_TEMPLATE_NAMES: Final[tuple[str, ...]] = (
    "acceptance-summary.json",
    "coverage-summary.txt",
    "environment-explicit.txt",
    "real-host-acceptance.json",
    "reviewer-signoff.md",
    "rollback-and-key-rotation.md",
    "test-summary.txt",
)
_GENERATED_NAMES: Final[frozenset[str]] = frozenset(
    {
        "candidate.json",
        "release-checklist.completed.md",
        "remote-artifacts.sha256",
        "schema-catalog.json",
        "source-artifacts.sha256",
        "versions.json",
        *_TEMPLATE_NAMES,
    }
)
EXPECTED_BUNDLE_NAMES: Final[frozenset[str]] = _GENERATED_NAMES | {EVIDENCE_MANIFEST_NAME}
_SECRET_PATTERNS: Final[tuple[re.Pattern[bytes], ...]] = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(rb"Authorization\s*:\s*\S+", re.IGNORECASE),
    re.compile(rb"Bearer\s+[A-Za-z0-9._~+/-]{8,}", re.IGNORECASE),
    re.compile(rb"(?:HMAC|SSH|APPROVAL)[_-]?KEY\s*[:=]\s*(?!PENDING_)\S+", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class ReleaseArtifactPaths:
    """Explicit fixed-role artifact inputs; paths are never serialized."""

    source_archive: Path
    wheel: Path
    sdist: Path
    bioprobe: Path
    bioexec: Path

    def as_mapping(self) -> dict[str, Path]:
        return {
            "source_archive": self.source_archive,
            "wheel": self.wheel,
            "sdist": self.sdist,
            "bioprobe": self.bioprobe,
            "bioexec": self.bioexec,
        }


def create_release_evidence(
    *,
    repository: str | Path,
    output_directory: str | Path,
    release_id: str,
    created_at: str,
    created_by: str,
    artifact_paths: ReleaseArtifactPaths,
) -> EvidenceVerification:
    """Build and atomically publish one sealed, explicitly unsigned bundle."""

    repository_path = Path(repository).absolute()
    output_path = Path(output_directory).absolute()
    if output_path.name != release_id:
        raise _validation_error("output directory name must equal the release identifier")
    commit = resolve_clean_repository_commit(repository_path)
    _validate_runtime_source_binding(repository_path, commit)
    artifact_hashes = {
        role: hash_release_artifact(path, role)
        for role, path in sorted(artifact_paths.as_mapping().items())
    }
    versions = _version_payload()
    catalog_bytes = _schema_catalog_bytes()
    catalog = _decode_json_object(catalog_bytes, role="schema_catalog")
    internal_catalog_digest = catalog.get("catalog_sha256")
    if (
        catalog.get("schema_version") != MVP_SCHEMA_VERSION
        or catalog.get("schema_count") != 21
        or not isinstance(internal_catalog_digest, str)
    ):
        raise _validation_error("installed schema catalog identity is invalid")

    try:
        candidate = ReleaseCandidate(
            release_id=release_id,
            git_commit=commit,
            controller_version=CONTROLLER_VERSION,
            probe_version=PROBE_VERSION,
            remote_executor_version=REMOTE_EXECUTOR_VERSION,
            compiler_version=COMPILER_VERSION,
            registry_version=versions["registry_version"],
            schema_version=MVP_SCHEMA_VERSION,
            cli_contract_version=CLI_CONTRACT_VERSION,
            schema_catalog_sha256=internal_catalog_digest,
            schema_catalog_file_sha256=hashlib.sha256(catalog_bytes).hexdigest(),
            source_archive_sha256=artifact_hashes["source_archive"],
            wheel_sha256=artifact_hashes["wheel"],
            sdist_sha256=artifact_hashes["sdist"],
            bioprobe_sha256=artifact_hashes["bioprobe"],
            bioexec_sha256=artifact_hashes["bioexec"],
            created_at=created_at,
            created_by=created_by,
        )
    except ValidationError as exc:
        raise _validation_error("release candidate identity is invalid") from exc

    canonical_checklist = _read_repository_resource(
        repository_path,
        Path("docs/release-checklist.md"),
        role="release_checklist",
    )
    payloads: dict[str, bytes] = {
        "candidate.json": _render_json(candidate.model_dump(mode="json")),
        "release-checklist.completed.md": instantiate_release_checklist(
            canonical_checklist,
            candidate,
        ),
        "schema-catalog.json": catalog_bytes,
        "versions.json": _render_json(versions),
        "source-artifacts.sha256": render_checksum_manifest(
            {
                ARTIFACT_LOGICAL_NAMES[role]: artifact_hashes[role]
                for role in ("sdist", "source_archive", "wheel")
            }
        ),
        "remote-artifacts.sha256": render_checksum_manifest(
            {
                ARTIFACT_LOGICAL_NAMES[role]: artifact_hashes[role]
                for role in ("bioexec", "bioprobe")
            }
        ),
    }
    replacements = {
        "PENDING_RELEASE_ID": candidate.release_id,
        "PENDING_SOURCE_GIT_COMMIT": candidate.git_commit,
    }
    for name in _TEMPLATE_NAMES:
        raw_template = _read_repository_resource(
            repository_path,
            _TEMPLATE_DIRECTORY / name,
            role=f"evidence_template_{name}",
        )
        payloads[name] = _render_template(raw_template, replacements, role=name)
    _validate_unsealed_payloads(payloads)
    _assert_no_sensitive_material(
        payloads,
        path_fragments=(
            repository_path,
            output_path,
            *artifact_paths.as_mapping().values(),
        ),
    )
    _require_repository_unchanged(repository_path, commit)
    payloads[EVIDENCE_MANIFEST_NAME] = checksum_payloads(payloads)
    _verify_payloads(payloads)
    EvidenceBundleStore(output_path).create(payloads)
    return verify_release_evidence(output_path)


def instantiate_release_checklist_file(
    *,
    repository: str | Path,
    output_file: str | Path,
    release_id: str,
    created_at: str,
    created_by: str,
) -> dict[str, str]:
    """Create one unsigned checklist record without replacing an existing file."""

    repository_path = Path(repository).absolute()
    commit = resolve_clean_repository_commit(repository_path)
    _validate_runtime_source_binding(repository_path, commit)
    try:
        candidate = ReleaseCandidate(
            release_id=release_id,
            git_commit=commit,
            controller_version=CONTROLLER_VERSION,
            probe_version=PROBE_VERSION,
            remote_executor_version=REMOTE_EXECUTOR_VERSION,
            compiler_version=COMPILER_VERSION,
            registry_version=REGISTRY_VERSION,
            schema_version=MVP_SCHEMA_VERSION,
            cli_contract_version=CLI_CONTRACT_VERSION,
            schema_catalog_sha256="0" * 64,
            schema_catalog_file_sha256="0" * 64,
            source_archive_sha256="0" * 64,
            wheel_sha256="0" * 64,
            sdist_sha256="0" * 64,
            bioprobe_sha256="0" * 64,
            bioexec_sha256="0" * 64,
            created_at=created_at,
            created_by=created_by,
        )
    except ValidationError as exc:
        raise _validation_error("release checklist identity is invalid") from exc
    canonical = _read_repository_resource(
        repository_path,
        Path("docs/release-checklist.md"),
        role="release_checklist",
    )
    payload = instantiate_release_checklist(canonical, candidate)
    _assert_no_sensitive_material(
        {"release-checklist.completed.md": payload},
        path_fragments=(repository_path, Path(output_file).absolute()),
    )
    _require_repository_unchanged(repository_path, commit)
    EvidenceBundleStore.create_file(output_file, payload)
    return {
        "git_commit": commit,
        "record_state": "DRAFT_UNREVIEWED",
        "release_decision": "BLOCKED",
        "release_id": release_id,
    }


def instantiate_release_checklist(
    canonical_payload: bytes,
    candidate: ReleaseCandidate,
) -> bytes:
    """Bind candidate facts while preserving every review box as unchecked."""

    try:
        canonical = canonical_payload.decode("utf-8")
    except UnicodeError as exc:
        raise _validation_error("canonical release checklist is not UTF-8") from exc
    if canonical.count("- [ ]") != 67 or "- [x]" in canonical.lower():
        raise _validation_error("canonical release checklist review boxes drifted")
    substitutions = {
        "- [ ] Release identifier: `________________`": (
            f"- [ ] Release identifier: `{candidate.release_id}` — generator-recorded; "
            "review pending"
        ),
        "- [ ] Exact Git commit: `________________`": (
            f"- [ ] Exact Git commit: `{candidate.git_commit}` — generator-recorded; review pending"
        ),
        "- [ ] Reviewer and date: `________________`": (
            "- [ ] Reviewer and date: `PENDING_INDEPENDENT_REVIEWER / PENDING_REVIEW_DATE`"
        ),
    }
    for source, replacement in substitutions.items():
        if canonical.count(source) != 1:
            raise _validation_error("canonical release checklist identity fields drifted")
        canonical = canonical.replace(source, replacement)
    header = f"""# Instantiated release-candidate checklist

> **Record state: `DRAFT_UNREVIEWED`**
> **Release decision: `BLOCKED`**
> This is an instantiated template, not reviewer or operator sign-off.

## Generator-recorded facts (not sign-off)

| Field | Value |
|---|---|
| Release identifier | `{candidate.release_id}` |
| Exact source Git commit | `{candidate.git_commit}` |
| Generated at | `{candidate.created_at}` |
| Evidence generator actor | `{candidate.created_by}` |

## Required external evidence

- [ ] Host platforms: `PENDING_REAL_HOST_PLATFORMS`
- [ ] Retained CI/demo evidence: `PENDING_RELEASE_ACCEPTANCE_CI`

---

"""
    rendered = (header + canonical).encode("utf-8")
    if rendered.lower().count(b"- [x]") != 0 or rendered.count(b"- [ ]") != 69:
        raise _validation_error("instantiated release checklist changed review state")
    return rendered


def seal_release_evidence(directory: str | Path) -> EvidenceVerification:
    """Create the aggregate checksum once for an exact unsealed evidence tree."""

    root = Path(directory).absolute()
    payloads = _read_evidence_directory(root, expected_names=_GENERATED_NAMES)
    _validate_unsealed_payloads(payloads)
    manifest = checksum_payloads(payloads)
    EvidenceBundleStore.create_file(root / EVIDENCE_MANIFEST_NAME, manifest)
    return verify_release_evidence(root)


def verify_release_evidence(directory: str | Path) -> EvidenceVerification:
    """Verify a sealed bundle without subprocess, network, or repository access."""

    payloads = _read_evidence_directory(
        Path(directory).absolute(),
        expected_names=EXPECTED_BUNDLE_NAMES,
    )
    return _verify_payloads(payloads)


def resolve_clean_repository_commit(repository: str | Path) -> str:
    """Return exact HEAD only when the selected worktree is clean."""

    root = Path(repository).absolute()
    try:
        metadata = root.lstat()
        if root.resolve(strict=True) != root or not stat.S_ISDIR(metadata.st_mode):
            raise OSError("unsafe repository root")
    except OSError as exc:
        raise _repository_error("repository_identity") from exc
    revision = _run_git(root, ("rev-parse", "--verify", "HEAD^{commit}"), stdout_limit=64)
    commit = revision.stdout.strip()
    if revision.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise _repository_error("git_commit")
    status = _run_git(
        root,
        (
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
        stdout_limit=1,
    )
    if status.stdout:
        raise _repository_error("git_worktree_clean")
    if status.returncode != 0:
        raise _repository_error("git_status")
    return commit


def _validate_runtime_source_binding(repository: Path, commit: str) -> None:
    """Require the candidate checkout to contain the exact running tool source."""

    try:
        candidate_tree = _git_source_tree_oid(repository, commit)
        runtime_tree = _runtime_source_tree_oid()
    except BioPipeError as exc:
        raise _validation_error(
            "candidate repository source does not match the running release tool"
        ) from exc
    if candidate_tree != runtime_tree:
        raise _validation_error(
            "candidate repository source does not match the running release tool"
        )


def _runtime_source_tree_oid() -> str:
    runtime_commit = resolve_clean_repository_commit(_RUNTIME_REPOSITORY_ROOT)
    return _git_source_tree_oid(_RUNTIME_REPOSITORY_ROOT, runtime_commit)


def _git_source_tree_oid(repository: Path, commit: str) -> str:
    result = _run_git(
        repository,
        ("rev-parse", "--verify", f"{commit}:src/biopipe"),
        stdout_limit=64,
    )
    tree_oid = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", tree_oid) is None:
        raise _repository_error("git_source_tree")
    object_type = _run_git(
        repository,
        ("cat-file", "-t", tree_oid),
        stdout_limit=8,
    )
    if object_type.returncode != 0 or object_type.stdout.strip() != "tree":
        raise _repository_error("git_source_tree")
    return tree_oid


def _require_repository_unchanged(repository: Path, expected_commit: str) -> None:
    try:
        observed_commit = resolve_clean_repository_commit(repository)
    except BioPipeError as exc:
        raise _repository_error("git_repository_changed") from exc
    if observed_commit != expected_commit:
        raise _repository_error("git_repository_changed")


def _run_git(
    repository: Path,
    arguments: tuple[str, ...],
    *,
    stdout_limit: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return run_bounded(
            (
                "git",
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-C",
                os.fspath(repository),
                *arguments,
            ),
            input_text="",
            timeout=_GIT_TIMEOUT_SECONDS,
            stdout_limit=stdout_limit,
            stderr_limit=1,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _repository_error("git_command") from exc


def _version_payload() -> dict[str, Any]:
    try:
        observed_registry = load_default_registry().version
    except (BioPipeError, RegistryValidationError) as exc:
        raise _validation_error("packaged registry identity is invalid") from exc
    if observed_registry != REGISTRY_VERSION:
        raise _validation_error("packaged registry version does not match the release constant")
    return {
        "cli_contract_version": CLI_CONTRACT_VERSION,
        "compiler_version": COMPILER_VERSION,
        "controller_version": CONTROLLER_VERSION,
        "exit_codes": {"command_failed": 2, "success": 0},
        "probe_version": PROBE_VERSION,
        "registry_version": observed_registry,
        "registry_version_expected": REGISTRY_VERSION,
        "remote_executor_version": REMOTE_EXECUTOR_VERSION,
        "schema_version": MVP_SCHEMA_VERSION,
    }


def _schema_catalog_bytes() -> bytes:
    try:
        payload = resources.files("biopipe").joinpath("schema_v1/catalog.json").read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise _validation_error("installed schema catalog is unavailable") from exc
    if not 0 < len(payload) <= _MAX_RESOURCE_BYTES:
        raise _validation_error("installed schema catalog exceeds its bound")
    return payload


def _read_repository_resource(repository: Path, relative: Path, *, role: str) -> bytes:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise _validation_error("release evidence resource path is invalid")
    return read_bounded_regular(repository / relative, role=role, limit_bytes=_MAX_RESOURCE_BYTES)


def _render_template(
    payload: bytes,
    replacements: Mapping[str, str],
    *,
    role: str,
) -> bytes:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise _validation_error("release evidence template is not UTF-8") from exc
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    if "PENDING_RELEASE_ID" in text or "PENDING_SOURCE_GIT_COMMIT" in text:
        raise _validation_error("release evidence template identity tokens are incomplete")
    rendered = text.encode("utf-8")
    if role.endswith(".json"):
        _decode_json_object(rendered, role=role)
    return rendered


def _validate_unsealed_payloads(payloads: Mapping[str, bytes]) -> None:
    if frozenset(payloads) != _GENERATED_NAMES:
        raise _validation_error("release evidence file set is incomplete")
    candidate = _candidate_from_payload(payloads["candidate.json"])
    versions = _decode_json_object(payloads["versions.json"], role="versions")
    expected_versions = {
        "cli_contract_version": candidate.cli_contract_version,
        "compiler_version": candidate.compiler_version,
        "controller_version": candidate.controller_version,
        "exit_codes": {"command_failed": 2, "success": 0},
        "probe_version": candidate.probe_version,
        "registry_version": candidate.registry_version,
        "registry_version_expected": candidate.registry_version,
        "remote_executor_version": candidate.remote_executor_version,
        "schema_version": candidate.schema_version,
    }
    if versions != expected_versions:
        raise _validation_error("versions evidence does not match candidate identity")
    catalog = _decode_json_object(payloads["schema-catalog.json"], role="schema_catalog")
    if (
        catalog.get("catalog_sha256") != candidate.schema_catalog_sha256
        or catalog.get("schema_version") != candidate.schema_version
        or catalog.get("schema_count") != 21
        or hashlib.sha256(payloads["schema-catalog.json"]).hexdigest()
        != candidate.schema_catalog_file_sha256
    ):
        raise _validation_error("schema catalog evidence does not match candidate identity")

    source = parse_checksum_manifest(
        payloads["source-artifacts.sha256"],
        expected_names=frozenset(
            {
                ARTIFACT_LOGICAL_NAMES["source_archive"],
                ARTIFACT_LOGICAL_NAMES["wheel"],
                ARTIFACT_LOGICAL_NAMES["sdist"],
            }
        ),
    )
    remote = parse_checksum_manifest(
        payloads["remote-artifacts.sha256"],
        expected_names=frozenset(
            {ARTIFACT_LOGICAL_NAMES["bioprobe"], ARTIFACT_LOGICAL_NAMES["bioexec"]}
        ),
    )
    if (
        source[ARTIFACT_LOGICAL_NAMES["source_archive"]] != candidate.source_archive_sha256
        or source[ARTIFACT_LOGICAL_NAMES["wheel"]] != candidate.wheel_sha256
        or source[ARTIFACT_LOGICAL_NAMES["sdist"]] != candidate.sdist_sha256
        or remote[ARTIFACT_LOGICAL_NAMES["bioprobe"]] != candidate.bioprobe_sha256
        or remote[ARTIFACT_LOGICAL_NAMES["bioexec"]] != candidate.bioexec_sha256
    ):
        raise _validation_error("artifact checksum evidence does not match candidate identity")
    checklist = payloads["release-checklist.completed.md"]
    if (
        b"Record state: `DRAFT_UNREVIEWED`" not in checklist
        or b"Release decision: `BLOCKED`" not in checklist
        or checklist.lower().count(b"- [x]") != 0
        or checklist.count(b"- [ ]") != 69
        or candidate.release_id.encode("ascii") not in checklist
        or candidate.git_commit.encode("ascii") not in checklist
    ):
        raise _validation_error("release checklist does not preserve unsigned review state")
    for name in ("acceptance-summary.json", "real-host-acceptance.json"):
        value = _decode_json_object(payloads[name], role=name)
        if (
            value.get("release_id") != candidate.release_id
            or value.get("source_git_commit") != candidate.git_commit
            or value.get("release_decision") != "BLOCKED"
        ):
            raise _validation_error("pending acceptance template identity is invalid")
    for name in ("reviewer-signoff.md", "rollback-and-key-rotation.md"):
        if (
            candidate.release_id.encode("ascii") not in payloads[name]
            or candidate.git_commit.encode("ascii") not in payloads[name]
            or b"BLOCKED" not in payloads[name]
        ):
            raise _validation_error("pending operator template identity is invalid")
    _assert_no_sensitive_material(payloads, path_fragments=())


def _verify_payloads(payloads: Mapping[str, bytes]) -> EvidenceVerification:
    if frozenset(payloads) != EXPECTED_BUNDLE_NAMES:
        raise _validation_error("sealed release evidence file set is incomplete")
    core = {name: payload for name, payload in payloads.items() if name != EVIDENCE_MANIFEST_NAME}
    _validate_unsealed_payloads(core)
    expected = parse_checksum_manifest(
        payloads[EVIDENCE_MANIFEST_NAME],
        expected_names=_GENERATED_NAMES,
    )
    observed = {name: hashlib.sha256(payload).hexdigest() for name, payload in sorted(core.items())}
    if expected != observed:
        raise _validation_error("release evidence aggregate checksum does not match")
    candidate = _candidate_from_payload(payloads["candidate.json"])
    return EvidenceVerification(
        release_id=candidate.release_id,
        git_commit=candidate.git_commit,
        evidence_manifest_sha256=hashlib.sha256(payloads[EVIDENCE_MANIFEST_NAME]).hexdigest(),
        file_count=len(payloads),
    )


def _read_evidence_directory(
    directory: Path,
    *,
    expected_names: frozenset[str],
) -> dict[str, bytes]:
    descriptor: int | None = None
    try:
        if directory.resolve(strict=True) != directory or not stat.S_ISDIR(
            directory.lstat().st_mode
        ):
            raise OSError("unsafe evidence directory")
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        observed_names = frozenset(os.listdir(descriptor))
        if observed_names != expected_names:
            raise OSError("evidence directory file set mismatch")
        payloads: dict[str, bytes] = {}
        total = 0
        for name in sorted(expected_names):
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
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not 0 < before.st_size <= _MAX_RESOURCE_BYTES
                ):
                    raise OSError("unsafe evidence file")
                payload = bytearray()
                while chunk := os.read(
                    file_descriptor,
                    min(1024 * 1024, _MAX_RESOURCE_BYTES + 1 - len(payload)),
                ):
                    payload.extend(chunk)
                    if len(payload) > _MAX_RESOURCE_BYTES:
                        raise OSError("evidence file exceeds limit")
                after = os.fstat(file_descriptor)
                if (
                    len(payload) != before.st_size
                    or before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                ):
                    raise OSError("evidence file changed while reading")
                payloads[name] = bytes(payload)
                total += len(payload)
            finally:
                os.close(file_descriptor)
        if total > _MAX_BUNDLE_BYTES:
            raise OSError("evidence bundle exceeds limit")
        return payloads
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "Release evidence is missing, unsafe, or not the exact expected file set.",
            remediation=["Use an unmodified create-only evidence bundle."],
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _candidate_from_payload(payload: bytes) -> ReleaseCandidate:
    try:
        return ReleaseCandidate.model_validate(_decode_json_object(payload, role="candidate"))
    except ValidationError as exc:
        raise _validation_error("candidate evidence is invalid") from exc


def _decode_json_object(payload: bytes, *, role: str) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _validation_error(f"{role} JSON evidence is invalid") from exc
    if not isinstance(value, dict):
        raise _validation_error(f"{role} JSON evidence must be an object")
    return cast(dict[str, Any], value)


def _render_json(value: Mapping[str, Any]) -> bytes:
    try:
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
    except (TypeError, ValueError) as exc:
        raise _validation_error("release evidence could not be serialized") from exc


def _assert_no_sensitive_material(
    payloads: Mapping[str, bytes],
    *,
    path_fragments: tuple[Path, ...],
) -> None:
    forbidden = {
        os.fspath(path.absolute()).encode("utf-8")
        for path in path_fragments
        if len(os.fspath(path.absolute())) >= 4
    }
    for payload in payloads.values():
        if any(pattern.search(payload) for pattern in _SECRET_PATTERNS):
            raise _validation_error("release evidence contains forbidden secret material")
        if any(fragment in payload for fragment in forbidden):
            raise _validation_error("release evidence contains a local path")


def _repository_error(operation: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "The release source repository is unavailable, unsafe, or not clean.",
        context={"operation": operation},
        remediation=["Use a clean checkout of the exact candidate commit."],
    )


def _validation_error(reason: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "Release evidence did not satisfy the reviewed format.",
        context={"reason": reason},
        remediation=["Use the fixed release-evidence templates and artifact roles."],
    )


__all__ = [
    "EVIDENCE_MANIFEST_NAME",
    "EXPECTED_BUNDLE_NAMES",
    "ReleaseArtifactPaths",
    "create_release_evidence",
    "instantiate_release_checklist",
    "instantiate_release_checklist_file",
    "resolve_clean_repository_commit",
    "seal_release_evidence",
    "verify_release_evidence",
]
