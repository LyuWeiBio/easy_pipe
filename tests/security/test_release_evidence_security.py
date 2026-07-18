"""Security boundaries for the private M6.1 release-evidence tooling."""

from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence import (
    ReleaseArtifactPaths,
    create_release_evidence,
    instantiate_release_checklist_file,
    resolve_clean_repository_commit,
    seal_release_evidence,
    verify_release_evidence,
)
from biopipe.release_evidence import generator as evidence_generator
from biopipe.release_evidence.store import EvidenceBundleStore

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_ID = "0.1.0-rc1"
COMMIT = "a" * 40
CREATED_AT = "2026-07-18T08:00:00Z"
CREATED_BY = "release-operator"


def _write_valid_artifacts(
    root: Path,
    *,
    path_sentinel: str = "artifacts",
    content_sentinel: bytes = b"",
) -> ReleaseArtifactPaths:
    artifact_root = root / path_sentinel
    artifact_root.mkdir(parents=True)
    payloads = {
        "source_archive": b"\x1f\x8bsource-archive\n" + content_sentinel,
        "wheel": b"PK\x03\x04wheel\n" + content_sentinel,
        "sdist": b"\x1f\x8bsdist\n" + content_sentinel,
        "bioprobe": b"#!/usr/bin/env python3\nPK\x03\x04probe\n" + content_sentinel,
        "bioexec": b"#!/usr/bin/env python3\nPK\x03\x04executor\n" + content_sentinel,
    }
    paths: dict[str, Path] = {}
    for role, payload in payloads.items():
        role_root = artifact_root / f"private-host-{role}"
        role_root.mkdir()
        path = role_root / f"patient-sample-{role}.private-artifact"
        path.write_bytes(payload)
        paths[role] = path
    return ReleaseArtifactPaths(**paths)


def _stub_clean_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        evidence_generator,
        "resolve_clean_repository_commit",
        lambda _repository: COMMIT,
    )
    monkeypatch.setattr(
        evidence_generator,
        "_validate_runtime_source_binding",
        lambda _repository, _commit: None,
    )


def _create_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    repository: Path = REPOSITORY_ROOT,
    output: Path | None = None,
    artifacts: ReleaseArtifactPaths | None = None,
    created_by: str = CREATED_BY,
) -> Path:
    _stub_clean_commit(monkeypatch)
    root = tmp_path.resolve()
    selected_artifacts = artifacts or _write_valid_artifacts(root)
    destination = output or root / RELEASE_ID
    create_release_evidence(
        repository=repository,
        output_directory=destination,
        release_id=RELEASE_ID,
        created_at=CREATED_AT,
        created_by=created_by,
        artifact_paths=selected_artifacts,
    )
    return destination


def _bundle_bytes(directory: Path) -> bytes:
    return b"\n".join(path.read_bytes() for path in sorted(directory.iterdir()) if path.is_file())


def _tree_state(path: Path) -> tuple[object, ...]:
    metadata = path.lstat()
    mode = stat.S_IFMT(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode):
        return (mode, os.readlink(path))
    if stat.S_ISREG(metadata.st_mode):
        return (mode, path.read_bytes())
    if stat.S_ISDIR(metadata.st_mode):
        children = tuple(
            (child.relative_to(path).as_posix(), _tree_state(child))
            for child in sorted(path.rglob("*"))
        )
        return (mode, children)
    return (mode, metadata.st_size)


def test_fixed_artifact_roles_do_not_disclose_supplied_paths_names_or_contents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_sentinel = "real-host.raw.internal__patient-sample-ALPHA"
    content_sentinel = b"artifact-content-must-not-enter-evidence"
    artifacts = _write_valid_artifacts(
        tmp_path.resolve(),
        path_sentinel=path_sentinel,
        content_sentinel=content_sentinel,
    )
    destination = _create_bundle(
        tmp_path,
        monkeypatch,
        artifacts=artifacts,
    )

    payload = _bundle_bytes(destination)
    assert path_sentinel.encode() not in payload
    assert content_sentinel not in payload
    for path in artifacts.as_mapping().values():
        assert os.fsencode(path) not in payload
        assert path.name.encode() not in payload
    assert b"easy-pipe-source.tar.gz" in payload
    assert b"easy-pipe-wheel.whl" in payload
    assert b"easy-pipe-sdist.tar.gz" in payload
    assert b"bioprobe.pyz" in payload
    assert b"bioexec.pyz" in payload


def test_actor_is_explicit_and_ambient_identity_or_secret_environment_is_not_collected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinels = {
        "HOSTNAME": "real-hostname.internal",
        "USER": "ambient-user-secret",
        "LOGNAME": "ambient-logname-secret",
        "SSH_AUTH_SOCK": "/private/ssh-agent-sensitive.sock",
        "BIOPIPE_APPROVAL_HMAC_KEY": "approval-hmac-sensitive-value",
        "SAMPLE_NAME": "patient-sample-sensitive-name",
        "RAWDATA_PATH": "/srv/private/patient/rawdata",
    }
    for name, value in sentinels.items():
        monkeypatch.setenv(name, value)

    def forbidden_identity_lookup() -> NoReturn:
        raise AssertionError("ambient identity lookup is forbidden")

    monkeypatch.setattr(socket, "gethostname", forbidden_identity_lookup)
    monkeypatch.setattr(getpass, "getuser", forbidden_identity_lookup)

    destination = _create_bundle(tmp_path, monkeypatch, created_by="explicit-release-bot")
    candidate = json.loads((destination / "candidate.json").read_text(encoding="utf-8"))
    payload = _bundle_bytes(destination)

    assert candidate["created_by"] == "explicit-release-bot"
    for value in sentinels.values():
        assert value.encode() not in payload


@pytest.mark.parametrize(
    "unsafe_kind",
    [
        "missing",
        "directory",
        "fifo",
        "leaf_symlink",
        "intermediate_symlink",
        "invalid_magic",
    ],
)
def test_unsafe_artifact_fails_without_destination_or_path_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    _stub_clean_commit(monkeypatch)
    root = tmp_path.resolve()
    artifacts = _write_valid_artifacts(root)
    sensitive = "patient-host__sample-secret__raw-path"
    unsafe_root = root / sensitive
    unsafe_root.mkdir()

    if unsafe_kind == "missing":
        unsafe = unsafe_root / "missing-private-wheel"
    elif unsafe_kind == "directory":
        unsafe = unsafe_root / "directory-private-wheel"
        unsafe.mkdir()
    elif unsafe_kind == "fifo":
        unsafe = unsafe_root / "fifo-private-wheel"
        os.mkfifo(unsafe)
    elif unsafe_kind == "leaf_symlink":
        target = unsafe_root / "actual-private-wheel"
        target.write_bytes(b"PK\x03\x04wheel\n")
        unsafe = unsafe_root / "linked-private-wheel"
        unsafe.symlink_to(target)
    elif unsafe_kind == "intermediate_symlink":
        target_root = root / "outside-private-artifacts"
        target_root.mkdir()
        (target_root / "actual-private-wheel").write_bytes(b"PK\x03\x04wheel\n")
        linked_root = unsafe_root / "linked-private-directory"
        linked_root.symlink_to(target_root, target_is_directory=True)
        unsafe = linked_root / "actual-private-wheel"
    else:
        unsafe = unsafe_root / "invalid-private-wheel"
        unsafe.write_bytes(b"not-a-wheel\n")

    destination = root / RELEASE_ID
    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=REPOSITORY_ROOT,
            output_directory=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=replace(artifacts, wheel=unsafe),
        )

    assert raised.value.code is ErrorCode.ARTIFACT_READ_FAILED
    assert raised.value.context == {"artifact_role": "wheel"}
    serialized = raised.value.to_json()
    assert sensitive not in serialized
    assert os.fspath(unsafe) not in serialized
    assert not os.path.lexists(destination)


@pytest.mark.parametrize("destination_kind", ["file", "empty_dir", "nonempty_dir", "symlink"])
def test_existing_candidate_destination_is_untouched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination_kind: str,
) -> None:
    _stub_clean_commit(monkeypatch)
    root = tmp_path.resolve()
    artifacts = _write_valid_artifacts(root)
    destination = root / RELEASE_ID
    if destination_kind == "file":
        destination.write_bytes(b"existing candidate file\n")
    elif destination_kind == "empty_dir":
        destination.mkdir()
    elif destination_kind == "nonempty_dir":
        destination.mkdir()
        (destination / "preserve.txt").write_bytes(b"existing candidate directory\n")
    else:
        external = root / "external-candidate"
        external.mkdir()
        (external / "preserve.txt").write_bytes(b"external content\n")
        destination.symlink_to(external, target_is_directory=True)
    before = _tree_state(destination)

    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=REPOSITORY_ROOT,
            output_directory=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=artifacts,
        )

    assert raised.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert _tree_state(destination) == before
    assert not list(root.glob(f".{RELEASE_ID}.biopipe-*"))


@pytest.mark.parametrize(
    "release_id",
    [
        "0.1.0",
        "v0.1.0-rc1",
        "0.1.0-rc0",
        "0.1.0-rc1\nprivate-host",
        "../0.1.0-rc1",
        "/absolute/0.1.0-rc1",
    ],
)
def test_unsafe_release_identifiers_fail_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    release_id: str,
) -> None:
    _stub_clean_commit(monkeypatch)
    root = tmp_path.resolve()
    artifacts = _write_valid_artifacts(root)
    destination = root / (release_id if "/" not in release_id else "safe-destination")

    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=REPOSITORY_ROOT,
            output_directory=destination,
            release_id=release_id,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=artifacts,
        )

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert not os.path.lexists(destination)


def test_output_directory_name_must_match_release_identifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_clean_commit(monkeypatch)
    root = tmp_path.resolve()
    destination = root / "different-candidate"

    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=REPOSITORY_ROOT,
            output_directory=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=_write_valid_artifacts(root),
        )

    assert raised.value.context == {
        "reason": "output directory name must equal the release identifier"
    }
    assert not destination.exists()


def test_dirty_git_path_name_is_not_exposed_in_repository_error(tmp_path: Path) -> None:
    sensitive = "real-host__patient-sample-ALPHA__rawdata.fastq.gz"
    repository = tmp_path.resolve() / "repository-with-private-location"
    repository.mkdir()

    def git(*arguments: str) -> None:
        subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    git("init", "--quiet")
    git("config", "user.name", "Release Test")
    git("config", "user.email", "release-test@example.invalid")
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    git("add", "tracked.txt")
    git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "initial")
    (repository / sensitive).write_text("untracked path only\n", encoding="utf-8")

    with pytest.raises(BioPipeError) as raised:
        resolve_clean_repository_commit(repository)

    serialized = raised.value.to_json()
    assert raised.value.context == {"operation": "git_worktree_clean"}
    assert sensitive not in serialized
    assert os.fspath(repository) not in serialized


def test_verifier_is_offline_and_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = _create_bundle(tmp_path, monkeypatch)
    before = {
        path.name: (
            path.read_bytes(),
            stat.S_IMODE(path.stat(follow_symlinks=False).st_mode),
            path.stat(follow_symlinks=False).st_mtime_ns,
        )
        for path in destination.iterdir()
    }

    def forbidden_external_call(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("offline verification attempted an external call")

    monkeypatch.setattr(subprocess, "Popen", forbidden_external_call)
    monkeypatch.setattr(subprocess, "run", forbidden_external_call)
    monkeypatch.setattr(socket, "socket", forbidden_external_call)
    monkeypatch.setattr(socket, "create_connection", forbidden_external_call)
    monkeypatch.setattr(evidence_generator, "run_bounded", forbidden_external_call)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("HOME", os.fspath(tmp_path / "nonexistent-home"))
    unrelated = tmp_path.resolve() / "unrelated-working-directory"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    verification = verify_release_evidence(destination)

    assert verification.integrity_status == "verified"
    assert verification.release_signoff_status == "pending"
    after = {
        path.name: (
            path.read_bytes(),
            stat.S_IMODE(path.stat(follow_symlinks=False).st_mode),
            path.stat(follow_symlinks=False).st_mtime_ns,
        )
        for path in destination.iterdir()
    }
    assert after == before


@pytest.mark.parametrize("mutation", ["expected_symlink", "extra_file", "tamper"])
def test_verifier_rejects_symlink_extra_file_and_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    destination = _create_bundle(tmp_path, monkeypatch)
    if mutation == "expected_symlink":
        candidate = destination / "candidate.json"
        outside = tmp_path.resolve() / "outside-candidate.json"
        outside.write_bytes(candidate.read_bytes())
        candidate.unlink()
        candidate.symlink_to(outside)
    elif mutation == "extra_file":
        (destination / "unexpected-private-report.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
    else:
        with (destination / "candidate.json").open("ab") as stream:
            stream.write(b"tampered\n")

    with pytest.raises(BioPipeError):
        verify_release_evidence(destination)


def test_private_key_material_in_repository_template_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_clean_commit(monkeypatch)
    root = tmp_path.resolve()
    repository = root / "repository-copy"
    (repository / "docs").mkdir(parents=True)
    shutil.copy2(
        REPOSITORY_ROOT / "docs/release-checklist.md",
        repository / "docs/release-checklist.md",
    )
    shutil.copytree(
        REPOSITORY_ROOT / "release-evidence/template",
        repository / "release-evidence/template",
    )
    shutil.copytree(
        REPOSITORY_ROOT / "src/biopipe",
        repository / "src/biopipe",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    key_header = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"
    template = repository / "release-evidence/template/test-summary.txt"
    template.write_bytes(template.read_bytes() + b"\n" + key_header + b"\nprivate-material\n")
    destination = root / RELEASE_ID

    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=repository,
            output_directory=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=_write_valid_artifacts(root),
        )

    assert raised.value.context == {"reason": "release evidence contains forbidden secret material"}
    assert "private-material" not in raised.value.to_json()
    assert not destination.exists()


def test_checklist_file_is_create_only_and_never_claims_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_clean_commit(monkeypatch)
    destination = tmp_path.resolve() / "release-checklist.completed.md"
    first = instantiate_release_checklist_file(
        repository=REPOSITORY_ROOT,
        output_file=destination,
        release_id=RELEASE_ID,
        created_at=CREATED_AT,
        created_by=CREATED_BY,
    )
    original = destination.read_bytes()

    assert first["record_state"] == "DRAFT_UNREVIEWED"
    assert first["release_decision"] == "BLOCKED"
    assert CREATED_BY.encode() in original
    assert original.lower().count(b"- [x]") == 0

    with pytest.raises(BioPipeError) as raised:
        instantiate_release_checklist_file(
            repository=REPOSITORY_ROOT,
            output_file=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
        )

    assert raised.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert destination.read_bytes() == original
    assert not {path.name for path in destination.parent.iterdir() if path.name.startswith(".")}


def test_sdist_manifest_cannot_recursively_collect_generated_evidence() -> None:
    manifest = (REPOSITORY_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()

    assert "recursive-include release-evidence *.md *.json *.txt" not in manifest
    assert "include release-evidence/README.md" in manifest
    assert "recursive-include release-evidence/template *.md *.json *.txt" in manifest


def test_candidate_repository_must_match_the_running_tool_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evidence_generator,
        "resolve_clean_repository_commit",
        lambda _repository: COMMIT,
    )
    monkeypatch.setattr(
        evidence_generator,
        "_git_source_tree_oid",
        lambda _repository, _commit: "a" * 40,
    )
    monkeypatch.setattr(
        evidence_generator,
        "_runtime_source_tree_oid",
        lambda: "b" * 40,
    )
    root = tmp_path.resolve()
    unrelated_repository = root / "unrelated-clean-repository"
    unrelated_repository.mkdir()
    destination = root / RELEASE_ID

    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=unrelated_repository,
            output_directory=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=_write_valid_artifacts(root),
        )

    assert raised.value.context == {
        "reason": "candidate repository source does not match the running release tool"
    }
    assert os.fspath(unrelated_repository) not in raised.value.to_json()
    assert not destination.exists()


def test_repository_commit_is_rechecked_before_bundle_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evidence_generator,
        "_validate_runtime_source_binding",
        lambda _repository, _commit: None,
    )
    commits = iter((COMMIT, "b" * 40))
    monkeypatch.setattr(
        evidence_generator,
        "resolve_clean_repository_commit",
        lambda _repository: next(commits),
    )
    root = tmp_path.resolve()
    destination = root / RELEASE_ID

    with pytest.raises(BioPipeError) as raised:
        create_release_evidence(
            repository=REPOSITORY_ROOT,
            output_directory=destination,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            created_by=CREATED_BY,
            artifact_paths=_write_valid_artifacts(root),
        )

    assert raised.value.context == {"operation": "git_repository_changed"}
    assert not destination.exists()


def test_checksum_sealing_reverifies_the_published_disk_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sealed = _create_bundle(tmp_path, monkeypatch)
    unsealed = tmp_path.resolve() / "unsealed"
    unsealed.mkdir(mode=0o700)
    for source in sealed.iterdir():
        if source.name != "SHA256SUMS":
            shutil.copy2(source, unsealed / source.name)

    original_create_file = EvidenceBundleStore.create_file

    def create_then_tamper(output_file: str | Path, payload: bytes) -> Path:
        created = original_create_file(output_file, payload)
        (Path(output_file).parent / "test-summary.txt").write_bytes(b"tampered after sealing\n")
        return created

    monkeypatch.setattr(
        EvidenceBundleStore,
        "create_file",
        staticmethod(create_then_tamper),
    )

    with pytest.raises(BioPipeError) as raised:
        seal_release_evidence(unsealed)

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert (unsealed / "SHA256SUMS").is_file()
    with pytest.raises(BioPipeError):
        verify_release_evidence(unsealed)


def test_create_only_store_rejects_a_shared_writable_parent(tmp_path: Path) -> None:
    shared_parent = tmp_path.resolve() / "shared-parent"
    shared_parent.mkdir(mode=0o777)
    shared_parent.chmod(0o777)

    with pytest.raises(BioPipeError) as raised:
        EvidenceBundleStore.create_file(shared_parent / "evidence.txt", b"private\n")

    assert raised.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert not (shared_parent / "evidence.txt").exists()
