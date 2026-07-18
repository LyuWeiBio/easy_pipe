"""Release-evidence identity, checksum, and offline verification contracts."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

import biopipe.release_evidence.generator as evidence_generator
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence import (
    EVIDENCE_MANIFEST_NAME,
    EXPECTED_BUNDLE_NAMES,
    ReleaseArtifactPaths,
    ReleaseCandidate,
    create_release_evidence,
    instantiate_release_checklist,
    verify_release_evidence,
)
from biopipe.release_evidence.checksums import (
    ARTIFACT_LOGICAL_NAMES,
    parse_checksum_manifest,
    render_checksum_manifest,
)
from biopipe.version import (
    CLI_CONTRACT_VERSION,
    COMPILER_VERSION,
    CONTROLLER_VERSION,
    MVP_SCHEMA_VERSION,
    PROBE_VERSION,
    REGISTRY_VERSION,
    REMOTE_EXECUTOR_VERSION,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_RELEASE_ID = "0.1.0-rc1"
_CREATED_AT = "2026-07-18T09:10:11Z"
_CREATED_BY = "release-operator"


@pytest.fixture(autouse=True)
def _bind_test_candidate_to_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        evidence_generator,
        "_validate_runtime_source_binding",
        lambda _repository, _commit: None,
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _candidate_payload() -> dict[str, object]:
    return {
        "evidence_format_version": "1.0",
        "release_id": _RELEASE_ID,
        "git_commit": "a" * 40,
        "controller_version": CONTROLLER_VERSION,
        "probe_version": PROBE_VERSION,
        "remote_executor_version": REMOTE_EXECUTOR_VERSION,
        "compiler_version": COMPILER_VERSION,
        "registry_version": REGISTRY_VERSION,
        "schema_version": MVP_SCHEMA_VERSION,
        "cli_contract_version": CLI_CONTRACT_VERSION,
        "schema_catalog_sha256": "b" * 64,
        "schema_catalog_file_sha256": "c" * 64,
        "source_archive_sha256": "d" * 64,
        "wheel_sha256": "e" * 64,
        "sdist_sha256": "f" * 64,
        "bioprobe_sha256": "1" * 64,
        "bioexec_sha256": "2" * 64,
        "created_at": _CREATED_AT,
        "created_by": _CREATED_BY,
        "record_state": "DRAFT_UNREVIEWED",
        "release_signoff_status": "pending",
    }


def _candidate() -> ReleaseCandidate:
    return ReleaseCandidate.model_validate(_candidate_payload())


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _clean_release_repository(root: Path) -> tuple[Path, str]:
    repository = root / "candidate-source"
    (repository / "docs").mkdir(parents=True)
    shutil.copy2(
        _PROJECT_ROOT / "docs" / "release-checklist.md",
        repository / "docs" / "release-checklist.md",
    )
    shutil.copytree(
        _PROJECT_ROOT / "release-evidence" / "template",
        repository / "release-evidence" / "template",
    )
    shutil.copytree(
        _PROJECT_ROOT / "src" / "biopipe",
        repository / "src" / "biopipe",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Release Evidence Test")
    _git(repository, "config", "user.email", "release-evidence@example.invalid")
    _git(repository, "config", "commit.gpgsign", "false")
    _git(repository, "add", "docs/release-checklist.md", "release-evidence/template", "src")
    _git(repository, "commit", "-q", "-m", "test: release evidence source")
    commit = _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""
    return repository, commit


def _fake_release_artifacts(root: Path) -> tuple[ReleaseArtifactPaths, dict[str, bytes]]:
    directory = root / "artifacts"
    directory.mkdir()
    payloads = {
        "source_archive": b"\x1f\x8bsource-archive\n",
        "wheel": b"PK\x03\x04wheel\n",
        "sdist": b"\x1f\x8bsdist\n",
        "bioprobe": b"#!/usr/bin/env python3\nPK\x03\x04bioprobe\n",
        "bioexec": b"#!/usr/bin/env python3\nPK\x03\x04bioexec\n",
    }
    paths: dict[str, Path] = {}
    for role, payload in payloads.items():
        path = directory / f"{role}.artifact"
        path.write_bytes(payload)
        paths[role] = path
    return ReleaseArtifactPaths(**paths), payloads


def _create_bundle(
    root: Path, *, parent_name: str = "evidence-a"
) -> tuple[Path, str, dict[str, bytes]]:
    repository, commit = _clean_release_repository(root)
    artifact_paths, artifact_payloads = _fake_release_artifacts(root)
    output_parent = root / parent_name
    output_parent.mkdir()
    output = output_parent / _RELEASE_ID
    created = create_release_evidence(
        repository=repository,
        output_directory=output,
        release_id=_RELEASE_ID,
        created_at=_CREATED_AT,
        created_by=_CREATED_BY,
        artifact_paths=artifact_paths,
    )
    assert created.release_id == _RELEASE_ID
    assert created.git_commit == commit
    assert created.file_count == len(EXPECTED_BUNDLE_NAMES)
    return output, commit, artifact_payloads


def test_release_candidate_is_strict_and_rejects_invalid_identity() -> None:
    candidate = _candidate()

    assert candidate.release_id == _RELEASE_ID
    assert candidate.record_state == "DRAFT_UNREVIEWED"
    assert candidate.release_signoff_status == "pending"

    invalid_updates: tuple[dict[str, object], ...] = (
        {"release_id": "../0.1.0-rc1"},
        {"git_commit": "A" * 40},
        {"schema_catalog_sha256": "b" * 63},
        {"created_at": "2026-07-18T09:10:11+00:00"},
        {"created_by": "operator/name"},
        {"controller_version": 1},
        {"record_state": "SIGNED"},
        {"release_signoff_status": "approved"},
        {"unexpected_field": "not allowed"},
    )
    for update in invalid_updates:
        payload = _candidate_payload()
        payload.update(update)
        with pytest.raises(ValidationError):
            ReleaseCandidate.model_validate(payload)


def test_checksum_manifest_render_and_parse_are_canonical() -> None:
    alpha_digest = "a" * 64
    zeta_digest = "f" * 64
    rendered = render_checksum_manifest({"zeta.txt": zeta_digest, "alpha.txt": alpha_digest})

    assert rendered == (f"{alpha_digest}  alpha.txt\n{zeta_digest}  zeta.txt\n".encode("ascii"))
    assert parse_checksum_manifest(
        rendered,
        expected_names=frozenset({"alpha.txt", "zeta.txt"}),
    ) == {"alpha.txt": alpha_digest, "zeta.txt": zeta_digest}

    malformed = (
        rendered.rstrip(b"\n"),
        rendered.replace(b"\n", b"\r\n"),
        f"{zeta_digest}  zeta.txt\n{alpha_digest}  alpha.txt\n".encode("ascii"),
        f"{'A' * 64}  alpha.txt\n{zeta_digest}  zeta.txt\n".encode("ascii"),
        f"{alpha_digest}  alpha.txt\n{alpha_digest}  alpha.txt\n".encode("ascii"),
    )
    for payload in malformed:
        with pytest.raises(ValueError):
            parse_checksum_manifest(
                payload,
                expected_names=frozenset({"alpha.txt", "zeta.txt"}),
            )


def test_checklist_instantiation_preserves_all_review_gates_unchecked() -> None:
    canonical = (_PROJECT_ROOT / "docs" / "release-checklist.md").read_bytes()
    rendered = instantiate_release_checklist(canonical, _candidate())

    assert canonical.count(b"- [ ]") == 67
    assert rendered.count(b"- [ ]") == 69
    assert rendered.lower().count(b"- [x]") == 0
    assert b"Record state: `DRAFT_UNREVIEWED`" in rendered
    assert b"Release decision: `BLOCKED`" in rendered
    assert _RELEASE_ID.encode("ascii") in rendered
    assert ("a" * 40).encode("ascii") in rendered
    assert b"PENDING_INDEPENDENT_REVIEWER / PENDING_REVIEW_DATE" in rendered
    assert b"PENDING_REAL_HOST_PLATFORMS" in rendered
    assert b"PENDING_RELEASE_ACCEPTANCE_CI" in rendered


def test_create_is_deterministic_and_bundle_identity_and_digests_are_correct(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    repository, commit = _clean_release_repository(root)
    artifact_paths, artifact_payloads = _fake_release_artifacts(root)
    first_parent = root / "evidence-a"
    second_parent = root / "evidence-b"
    first_parent.mkdir()
    second_parent.mkdir()
    first = first_parent / _RELEASE_ID
    second = second_parent / _RELEASE_ID

    first_result = create_release_evidence(
        repository=repository,
        output_directory=first,
        release_id=_RELEASE_ID,
        created_at=_CREATED_AT,
        created_by=_CREATED_BY,
        artifact_paths=artifact_paths,
    )
    second_result = create_release_evidence(
        repository=repository,
        output_directory=second,
        release_id=_RELEASE_ID,
        created_at=_CREATED_AT,
        created_by=_CREATED_BY,
        artifact_paths=artifact_paths,
    )

    first_payloads = {path.name: path.read_bytes() for path in first.iterdir()}
    second_payloads = {path.name: path.read_bytes() for path in second.iterdir()}
    assert first_payloads == second_payloads
    assert frozenset(first_payloads) == EXPECTED_BUNDLE_NAMES
    assert first_result == second_result == verify_release_evidence(first)

    candidate = ReleaseCandidate.model_validate_json(first_payloads["candidate.json"])
    versions = json.loads(first_payloads["versions.json"])
    catalog = json.loads(first_payloads["schema-catalog.json"])
    assert candidate.git_commit == commit
    assert candidate.created_at == _CREATED_AT
    assert candidate.created_by == _CREATED_BY
    assert versions == {
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
    assert catalog["schema_count"] == 21
    assert candidate.schema_catalog_sha256 == catalog["catalog_sha256"]
    assert candidate.schema_catalog_file_sha256 == _sha256(first_payloads["schema-catalog.json"])

    expected_artifact_hashes = {
        role: _sha256(payload) for role, payload in artifact_payloads.items()
    }
    assert candidate.source_archive_sha256 == expected_artifact_hashes["source_archive"]
    assert candidate.wheel_sha256 == expected_artifact_hashes["wheel"]
    assert candidate.sdist_sha256 == expected_artifact_hashes["sdist"]
    assert candidate.bioprobe_sha256 == expected_artifact_hashes["bioprobe"]
    assert candidate.bioexec_sha256 == expected_artifact_hashes["bioexec"]
    assert parse_checksum_manifest(
        first_payloads["source-artifacts.sha256"],
        expected_names=frozenset(
            {
                ARTIFACT_LOGICAL_NAMES["source_archive"],
                ARTIFACT_LOGICAL_NAMES["wheel"],
                ARTIFACT_LOGICAL_NAMES["sdist"],
            }
        ),
    ) == {
        ARTIFACT_LOGICAL_NAMES[role]: expected_artifact_hashes[role]
        for role in ("source_archive", "wheel", "sdist")
    }
    assert parse_checksum_manifest(
        first_payloads["remote-artifacts.sha256"],
        expected_names=frozenset(
            {ARTIFACT_LOGICAL_NAMES["bioprobe"], ARTIFACT_LOGICAL_NAMES["bioexec"]}
        ),
    ) == {
        ARTIFACT_LOGICAL_NAMES[role]: expected_artifact_hashes[role]
        for role in ("bioprobe", "bioexec")
    }

    aggregate = parse_checksum_manifest(
        first_payloads[EVIDENCE_MANIFEST_NAME],
        expected_names=EXPECTED_BUNDLE_NAMES - {EVIDENCE_MANIFEST_NAME},
    )
    assert aggregate == {
        name: _sha256(payload)
        for name, payload in first_payloads.items()
        if name != EVIDENCE_MANIFEST_NAME
    }
    identity_templates = (
        "acceptance-summary.json",
        "real-host-acceptance.json",
        "reviewer-signoff.md",
        "rollback-and-key-rotation.md",
    )
    for name in identity_templates:
        payload = first_payloads[name]
        assert b"PENDING_RELEASE_ID" not in payload
        assert b"PENDING_SOURCE_GIT_COMMIT" not in payload
        assert _RELEASE_ID.encode("ascii") in payload
        assert commit.encode("ascii") in payload


def test_verify_rejects_checksum_tampering(tmp_path: Path) -> None:
    output, _commit, _artifacts = _create_bundle(tmp_path.resolve())
    manifest = output / EVIDENCE_MANIFEST_NAME
    payload = manifest.read_bytes()
    replacement = b"0" if payload[:1] != b"0" else b"1"
    manifest.write_bytes(replacement + payload[1:])

    with pytest.raises(BioPipeError) as exc_info:
        verify_release_evidence(output)

    assert exc_info.value.code is ErrorCode.VALIDATION_FAILED


def test_verify_rejects_a_missing_evidence_file(tmp_path: Path) -> None:
    output, _commit, _artifacts = _create_bundle(tmp_path.resolve())
    (output / "test-summary.txt").unlink()

    with pytest.raises(BioPipeError) as exc_info:
        verify_release_evidence(output)

    assert exc_info.value.code is ErrorCode.ARTIFACT_READ_FAILED


def test_verify_rejects_an_extra_evidence_file(tmp_path: Path) -> None:
    output, _commit, _artifacts = _create_bundle(tmp_path.resolve())
    (output / "unexpected.txt").write_text("not part of the sealed set\n", encoding="utf-8")

    with pytest.raises(BioPipeError) as exc_info:
        verify_release_evidence(output)

    assert exc_info.value.code is ErrorCode.ARTIFACT_READ_FAILED
