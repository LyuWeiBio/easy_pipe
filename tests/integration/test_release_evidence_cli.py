"""Subprocess acceptance tests for the repository-local M6.1 evidence tool."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "create_release_evidence.py"


def test_release_evidence_cli_create_verify_and_create_only(tmp_path: Path) -> None:
    candidate_repository = _candidate_repository(tmp_path)
    ignored_secret = candidate_repository / "src/biopipe/operator-hmac.key"
    with (candidate_repository / ".git/info/exclude").open("a", encoding="utf-8") as stream:
        stream.write("\n/src/biopipe/operator-hmac.key\n")
    secret_marker = b"ignored-private-key-material-must-not-be-read"
    ignored_secret.write_bytes(secret_marker)
    ignored_secret.chmod(0o000)
    artifacts = _release_artifacts(tmp_path)
    output_parent = tmp_path / "evidence"
    output_parent.mkdir()
    output = output_parent / "0.1.0-rc1"

    created = _run(
        "create",
        "--repository",
        str(candidate_repository),
        "--release-id",
        "0.1.0-rc1",
        "--created-at",
        "2026-07-18T08:00:00Z",
        "--created-by",
        "release-operator-01",
        "--output",
        str(output),
        *artifacts,
    )

    assert created.returncode == 0, created.stderr
    created_result = json.loads(created.stdout)
    assert created_result["status"] == "evidence_created_unreviewed"
    assert created_result["integrity_status"] == "verified"
    assert created_result["release_signoff_status"] == "pending"
    assert created_result["file_count"] == 14
    assert set(path.name for path in output.iterdir()) == {
        "SHA256SUMS",
        "acceptance-summary.json",
        "candidate.json",
        "coverage-summary.txt",
        "environment-explicit.txt",
        "real-host-acceptance.json",
        "release-checklist.completed.md",
        "remote-artifacts.sha256",
        "reviewer-signoff.md",
        "rollback-and-key-rotation.md",
        "schema-catalog.json",
        "source-artifacts.sha256",
        "test-summary.txt",
        "versions.json",
    }
    assert secret_marker not in b"".join(path.read_bytes() for path in output.iterdir())
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert stat.S_IMODE((output / "candidate.json").stat().st_mode) == 0o600

    verify_environment = {**os.environ, "HOME": str(tmp_path / "missing-home"), "PATH": ""}
    verified = _run(
        "verify",
        "--directory",
        str(output),
        env=verify_environment,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["status"] == "evidence_integrity_verified"

    duplicate = _run(
        "create",
        "--repository",
        str(candidate_repository),
        "--release-id",
        "0.1.0-rc1",
        "--created-at",
        "2026-07-18T08:00:00Z",
        "--created-by",
        "release-operator-01",
        "--output",
        str(output),
        *artifacts,
    )
    assert duplicate.returncode == 2
    error = json.loads(duplicate.stderr)["error"]
    assert error["code"] == "ARTIFACT_WRITE_FAILED"
    assert str(output) not in duplicate.stderr
    assert (output / "candidate.json").read_bytes()


def test_release_evidence_cli_checklist_and_checksum_sealing(tmp_path: Path) -> None:
    candidate_repository = _candidate_repository(tmp_path)
    artifacts = _release_artifacts(tmp_path)
    output_parent = tmp_path / "evidence"
    output_parent.mkdir()
    sealed = output_parent / "0.1.0-rc1"
    created = _run(
        "create",
        "--repository",
        str(candidate_repository),
        "--release-id",
        "0.1.0-rc1",
        "--created-at",
        "2026-07-18T08:00:00Z",
        "--created-by",
        "release-operator-01",
        "--output",
        str(sealed),
        *artifacts,
    )
    assert created.returncode == 0, created.stderr

    unsealed = output_parent / "unsealed"
    unsealed.mkdir(mode=0o700)
    for source in sealed.iterdir():
        if source.name != "SHA256SUMS":
            shutil.copyfile(source, unsealed / source.name)
    checksum_result = _run("checksums", "--directory", str(unsealed))
    assert checksum_result.returncode == 0, checksum_result.stderr
    assert json.loads(checksum_result.stdout)["status"] == "evidence_integrity_sealed"
    assert (unsealed / "SHA256SUMS").is_file()
    repeated = _run("checksums", "--directory", str(unsealed))
    assert repeated.returncode == 2
    assert json.loads(repeated.stderr)["error"]["code"] == "ARTIFACT_READ_FAILED"

    checklist = output_parent / "candidate-checklist.md"
    instantiated = _run(
        "checklist",
        "--repository",
        str(candidate_repository),
        "--release-id",
        "0.1.0-rc1",
        "--created-at",
        "2026-07-18T08:00:00Z",
        "--created-by",
        "release-operator-01",
        "--output",
        str(checklist),
    )
    assert instantiated.returncode == 0, instantiated.stderr
    text = checklist.read_text(encoding="utf-8")
    assert text.count("- [ ]") == 69
    assert "- [x]" not in text.lower()
    assert "DRAFT_UNREVIEWED" in text
    assert "BLOCKED" in text
    assert "PENDING_INDEPENDENT_REVIEWER" in text


def test_release_evidence_cli_error_does_not_echo_dirty_path(tmp_path: Path) -> None:
    candidate_repository = _candidate_repository(tmp_path)
    dirty_name = "private-host_rawdata_Sample-Patient-01.fastq"
    (candidate_repository / dirty_name).write_text("synthetic marker", encoding="utf-8")
    artifacts = _release_artifacts(tmp_path)
    output_parent = tmp_path / "evidence"
    output_parent.mkdir()

    result = _run(
        "create",
        "--repository",
        str(candidate_repository),
        "--release-id",
        "0.1.0-rc1",
        "--created-at",
        "2026-07-18T08:00:00Z",
        "--created-by",
        "release-operator-01",
        "--output",
        str(output_parent / "0.1.0-rc1"),
        *artifacts,
    )

    assert result.returncode == 2
    assert dirty_name not in result.stderr
    assert str(candidate_repository) not in result.stderr
    assert json.loads(result.stderr)["error"]["context"]["operation"] == ("git_worktree_clean")


def _candidate_repository(tmp_path: Path) -> Path:
    root = tmp_path / "candidate-repository"
    (root / "docs").mkdir(parents=True)
    (root / "scripts").mkdir()
    shutil.copyfile(
        REPOSITORY_ROOT / "docs" / "release-checklist.md",
        root / "docs" / "release-checklist.md",
    )
    shutil.copytree(
        REPOSITORY_ROOT / "release-evidence" / "template",
        root / "release-evidence" / "template",
    )
    shutil.copytree(
        REPOSITORY_ROOT / "src" / "biopipe",
        root / "src" / "biopipe",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    shutil.copy2(SCRIPT, root / "scripts" / SCRIPT.name)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Evidence Test")
    _git(root, "config", "user.email", "evidence@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "candidate")
    return root.resolve()


def _release_artifacts(tmp_path: Path) -> list[str]:
    root = tmp_path / "artifact-private-host_rawdata_Sample-Patient-01"
    root.mkdir()
    source_archive = root / "source-private-host.tar.gz"
    sdist = root / "sdist-Sample-Patient-01.tar.gz"
    wheel = root / "wheel-rawdata.whl"
    bioprobe = root / "probe-private-host.pyz"
    bioexec = root / "executor-private-host.pyz"
    source_archive.write_bytes(gzip.compress(b"anonymous source archive"))
    sdist.write_bytes(gzip.compress(b"anonymous source distribution"))
    _write_zip(wheel, b"anonymous wheel")
    _write_zipapp(bioprobe, b"anonymous probe")
    _write_zipapp(bioexec, b"anonymous executor")
    return [
        "--source-archive",
        str(source_archive),
        "--wheel",
        str(wheel),
        "--sdist",
        str(sdist),
        "--bioprobe",
        str(bioprobe),
        "--bioexec",
        str(bioexec),
    ]


def _write_zip(path: Path, payload: bytes) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("METADATA", payload)


def _write_zipapp(path: Path, payload: bytes) -> None:
    archive_path = path.with_suffix(".zip")
    _write_zip(archive_path, payload)
    path.write_bytes(b"#!/usr/bin/env python3\n" + archive_path.read_bytes())


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _run(*arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    script = SCRIPT
    if "--repository" in arguments:
        repository_index = arguments.index("--repository") + 1
        script = Path(arguments[repository_index]) / "scripts" / SCRIPT.name
    process_environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    if env is not None:
        process_environment.update(env)
    return subprocess.run(
        [sys.executable, str(script), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=process_environment,
    )
