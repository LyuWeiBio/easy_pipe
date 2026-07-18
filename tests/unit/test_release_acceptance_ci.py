"""Contracts for sanitized M6.1 release-acceptance CI evidence."""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from biopipe.errors import BioPipeError
from biopipe.release_evidence import generator as evidence_generator
from biopipe.release_evidence.acceptance import (
    ACCEPTANCE_EVIDENCE_NAMES,
    AcceptanceArtifactPaths,
    create_release_acceptance_evidence,
    verify_native_environment_export,
    verify_release_acceptance_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
JUNIT_SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_release_acceptance_junit.py"
RELEASE_ID = "0.1.0-rc1"
CREATED_AT = "2026-07-18T12:00:00Z"
CI_RUN_ID = "123456"
PACKAGE_URL = "https://conda.anaconda.org/conda-forge/linux-64/python-3.12.11-h1234567_0.conda"
PACKAGE_MD5 = "a" * 32


@pytest.fixture(autouse=True)
def _allow_fixture_repository_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "biopipe.release_evidence.acceptance.validate_runtime_repository_binding",
        lambda _repository, _commit: None,
    )


def _junit_module() -> object:
    spec = importlib.util.spec_from_file_location("release_acceptance_junit", JUNIT_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


junit = _junit_module()


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _explicit(*, header: str = "# platform: linux-64", url: str = PACKAGE_URL) -> bytes:
    return f"{header}\n@EXPLICIT\n{url}#{PACKAGE_MD5}\n".encode("ascii")


def _repository(root: Path) -> tuple[Path, str]:
    repository = root / "candidate"
    locks = repository / "environments" / "locks"
    locks.mkdir(parents=True)
    (locks / "linux-64.explicit.txt").write_bytes(_explicit(header="# target-platform: linux-64"))
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Acceptance Test")
    _git(repository, "config", "user.email", "acceptance@example.invalid")
    _git(repository, "config", "commit.gpgsign", "false")
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "test: candidate lock")
    return repository.resolve(), _git(repository, "rev-parse", "HEAD")


def _write_zip(path: Path, payload: bytes) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload", payload)


def _artifacts(root: Path) -> AcceptanceArtifactPaths:
    directory = root / "artifacts"
    directory.mkdir(parents=True)
    wheel = directory / "easy_pipe.whl"
    sdist = directory / "easy_pipe.tar.gz"
    probe_first = directory / "bioprobe-a.pyz"
    probe_second = directory / "bioprobe-b.pyz"
    executor_first = directory / "bioexec-a.pyz"
    executor_second = directory / "bioexec-b.pyz"
    _write_zip(wheel, b"wheel")
    sdist.write_bytes(gzip.compress(b"sdist"))
    for path, payload in (
        (probe_first, b"probe"),
        (probe_second, b"probe"),
        (executor_first, b"executor"),
        (executor_second, b"executor"),
    ):
        archive = path.with_suffix(".zip")
        _write_zip(archive, payload)
        path.write_bytes(b"#!/usr/bin/env python3\n" + archive.read_bytes())
    return AcceptanceArtifactPaths(
        wheel=wheel,
        sdist=sdist,
        bioprobe_first=probe_first,
        bioprobe_second=probe_second,
        bioexec_first=executor_first,
        bioexec_second=executor_second,
    )


def _test_result(root: Path) -> Path:
    path = root / "test-result.json"
    path.write_text(
        json.dumps(
            {"errors": 0, "failures": 0, "skipped": 0, "status": "passed", "tests": 3},
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )
    return path


def _junit_xml(
    *,
    third_name: str = "test_m6_anonymous_release_acceptance",
    third_child: str = "",
    failures: int = 0,
    skipped: int = 0,
) -> str:
    return f"""<testsuites name="pytest tests">
<testsuite errors="0" failures="{failures}" skipped="{skipped}" tests="3">
<testcase
  classname="tests.integration.test_m5_controller_executor_e2e"
  name="test_controller_executor_local_acceptance_is_gated_audited_and_shell_free" />
<testcase
  classname="tests.integration.test_m6_release_acceptance"
  name="test_m6_runtime_identity_gate_rejects_unlocked_versions" />
<testcase
  classname="tests.integration.test_m6_release_acceptance"
  name="{third_name}">{third_child}</testcase>
</testsuite>
</testsuites>
"""


def _create(root: Path) -> tuple[Path, str]:
    repository, commit = _repository(root)
    export = root / "native-export.txt"
    export.write_bytes(_explicit())
    artifacts = _artifacts(root)
    result = _test_result(root)
    parent = root / "evidence"
    parent.mkdir(mode=0o700)
    output = parent / "release-acceptance"
    created = create_release_acceptance_evidence(
        repository=repository,
        output_directory=output,
        release_id=RELEASE_ID,
        created_at=CREATED_AT,
        ci_run_id=CI_RUN_ID,
        environment_export=export,
        test_result=result,
        artifact_paths=artifacts,
    )
    assert created["status"] == "release_acceptance_evidence_created_unreviewed"
    return output, commit


def test_native_export_must_exactly_match_the_platform_lock(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    export = tmp_path / "native-export.txt"
    export.write_bytes(_explicit())

    result = verify_native_environment_export(
        repository=repository,
        environment_export=export,
        platform="linux-64",
    )
    assert result["package_count"] == 1
    assert result["status"] == "verified_against_committed_lock"

    export.write_bytes(_explicit(url=PACKAGE_URL.replace("3.12.11", "3.12.10")))
    with pytest.raises(BioPipeError, match="reviewed format"):
        verify_native_environment_export(
            repository=repository,
            environment_export=export,
            platform="linux-64",
        )


def test_native_export_requires_a_clean_committed_lock(tmp_path: Path) -> None:
    repository = tmp_path / "not-a-repository"
    locks = repository / "environments" / "locks"
    locks.mkdir(parents=True)
    (locks / "linux-64.explicit.txt").write_bytes(_explicit())
    export = tmp_path / "native-export.txt"
    export.write_bytes(_explicit())

    with pytest.raises(BioPipeError):
        verify_native_environment_export(
            repository=repository,
            environment_export=export,
            platform="linux-64",
        )


def test_runtime_repository_binding_rejects_a_different_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _runtime_commit = _repository(tmp_path / "runtime")
    candidate, candidate_commit = _repository(tmp_path / "selected")
    monkeypatch.setattr(evidence_generator, "_RUNTIME_REPOSITORY_ROOT", runtime)

    evidence_generator.validate_runtime_repository_binding(candidate, candidate_commit)
    (candidate / "different.txt").write_text("different\n", encoding="ascii")
    _git(candidate, "add", "different.txt")
    _git(candidate, "commit", "-qm", "test: different tree")
    with pytest.raises(BioPipeError, match="reviewed format"):
        evidence_generator.validate_runtime_repository_binding(
            candidate,
            _git(candidate, "rev-parse", "HEAD"),
        )


def test_repository_identity_ignores_git_replace_objects(tmp_path: Path) -> None:
    repository, original_commit = _repository(tmp_path)
    (repository / "replacement.txt").write_text("replacement\n", encoding="ascii")
    _git(repository, "add", "replacement.txt")
    _git(repository, "commit", "-qm", "test: replacement tree")
    replacement_commit = _git(repository, "rev-parse", "HEAD")
    _git(repository, "replace", original_commit, replacement_commit)
    _git(repository, "reset", "--hard", original_commit)
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


def test_repository_identity_ignores_inherited_git_location(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other_repository, other_commit = _repository(tmp_path / "other")
    selected = tmp_path / "selected-not-a-repository"
    selected.mkdir()
    monkeypatch.setenv("GIT_DIR", str(other_repository / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other_repository))
    assert _git(selected, "rev-parse", "HEAD") == other_commit

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(selected)


def test_repository_identity_overrides_local_core_worktree(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    alternate = tmp_path / "alternate"
    alternate_lock = alternate / "environments" / "locks" / "linux-64.explicit.txt"
    alternate_lock.parent.mkdir(parents=True)
    tracked_lock = repository / "environments" / "locks" / "linux-64.explicit.txt"
    alternate_lock.write_bytes(tracked_lock.read_bytes())
    _git(repository, "config", "core.worktree", str(alternate))
    tracked_lock.write_bytes(_explicit(url=PACKAGE_URL.replace("3.12.11", "3.12.10")))
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


def test_repository_identity_hashes_raw_bytes_despite_stat_configuration(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    tracked = repository / "stat-tracked.txt"
    tracked.write_bytes(b"A" * 29)
    old_time = tracked.stat().st_mtime_ns - 10_000_000_000
    os.utime(tracked, ns=(old_time, old_time))
    _git(repository, "add", "stat-tracked.txt")
    _git(repository, "commit", "-qm", "test: add stat fixture")
    before = tracked.stat()
    _git(repository, "config", "core.trustctime", "false")
    _git(repository, "config", "core.checkStat", "minimal")
    tracked.write_bytes(b"B" * 29)
    os.utime(tracked, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


def test_repository_identity_compares_raw_executable_mode(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    tracked_lock = repository / "environments" / "locks" / "linux-64.explicit.txt"
    _git(repository, "config", "core.fileMode", "false")
    tracked_lock.chmod(stat.S_IMODE(tracked_lock.stat().st_mode) | stat.S_IXUSR)
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


def test_repository_identity_requires_owner_execute_for_committed_scripts(
    tmp_path: Path,
) -> None:
    repository, _commit = _repository(tmp_path)
    script = repository / "tracked-script.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    script.chmod(0o755)
    _git(repository, "add", "tracked-script.sh")
    _git(repository, "commit", "-qm", "test: add executable fixture")
    _git(repository, "config", "core.fileMode", "false")
    script.chmod(0o650)
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


def test_repository_identity_rejects_locally_excluded_source(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    local_exclude = repository / ".git" / "info" / "exclude"
    local_exclude.write_text("src/biopipe/extra.py\n", encoding="ascii")
    hidden_source = repository / "src" / "biopipe" / "extra.py"
    hidden_source.parent.mkdir(parents=True)
    hidden_source.write_text("VALUE = 'not committed'\n", encoding="ascii")
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert evidence_generator.resolve_clean_repository_commit(repository) == commit

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(
            repository,
            require_no_ignored_untracked=True,
        )


def test_repository_identity_does_not_trust_clean_filters(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    tracked = repository / "filtered.txt"
    tracked.write_text("ORIGINAL\n", encoding="ascii")
    _git(repository, "add", "filtered.txt")
    _git(repository, "commit", "-qm", "test: add filter fixture")
    attributes = repository / ".git" / "info" / "attributes"
    attributes.write_text("filtered.txt filter=hide-change\n", encoding="ascii")
    _git(repository, "config", "filter.hide-change.clean", "sed s/CHANGED!/ORIGINAL/g")
    tracked.write_text("CHANGED!\n", encoding="ascii")
    assert _git(repository, "check-attr", "filter", "--", "filtered.txt").endswith(
        "filter: hide-change"
    )
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


@pytest.mark.parametrize("index_option", ["--assume-unchanged", "--skip-worktree"])
def test_repository_identity_rejects_hidden_index_state(
    tmp_path: Path,
    index_option: str,
) -> None:
    repository, _commit = _repository(tmp_path)
    relative_lock = "environments/locks/linux-64.explicit.txt"
    tracked_lock = repository / relative_lock
    _git(repository, "update-index", index_option, relative_lock)
    tracked_lock.write_bytes(_explicit(url=PACKAGE_URL.replace("3.12.11", "3.12.10")))
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert not _git(repository, "ls-files", "-v", relative_lock).startswith("H ")

    with pytest.raises(BioPipeError):
        evidence_generator.resolve_clean_repository_commit(repository)


def test_native_export_rejects_credentials_and_non_public_sources(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    export = tmp_path / "native-export.txt"
    unsafe_urls = (
        PACKAGE_URL.replace("https://", "https://token@"),
        PACKAGE_URL.replace("conda.anaconda.org", "private.example"),
        PACKAGE_URL.replace("https://", "file:///"),
        PACKAGE_URL + "?token=secret",
    )
    for url in unsafe_urls:
        export.write_bytes(_explicit(url=url))
        with pytest.raises(BioPipeError):
            verify_native_environment_export(
                repository=repository,
                environment_export=export,
                platform="linux-64",
            )


def test_ci_evidence_is_create_only_sanitized_and_offline_verifiable(tmp_path: Path) -> None:
    output, commit = _create(tmp_path)

    assert {path.name for path in output.iterdir()} == ACCEPTANCE_EVIDENCE_NAMES
    verified = verify_release_acceptance_evidence(output)
    assert verified["acceptance_status"] == "passed"
    assert verified["release_decision"] == "BLOCKED"
    assert verified["release_id"] == RELEASE_ID
    assert verified["source_git_commit"] == commit
    assert verified["file_count"] == len(ACCEPTANCE_EVIDENCE_NAMES)
    summary = json.loads((output / "acceptance-summary.json").read_text(encoding="utf-8"))
    assert summary["real_remote_host_exercised"] is False
    assert summary["real_ssh_exercised"] is False
    assert summary["real_container_runtime_exercised"] is False
    assert summary["independent_review_status"] == "pending"
    combined = b"".join(path.read_bytes() for path in output.iterdir())
    assert b"/Users/" not in combined
    assert b"/home/" not in combined
    assert b"approval.key" not in combined
    if sys.platform != "win32":
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())

    with pytest.raises(BioPipeError):
        create_release_acceptance_evidence(
            repository=tmp_path / "candidate",
            output_directory=output,
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            ci_run_id=CI_RUN_ID,
            environment_export=tmp_path / "native-export.txt",
            test_result=tmp_path / "test-result.json",
            artifact_paths=_artifacts(tmp_path / "duplicate-artifacts"),
        )


def test_ci_evidence_rejects_zipapp_drift_and_test_skips(tmp_path: Path) -> None:
    repository, _commit = _repository(tmp_path)
    export = tmp_path / "native-export.txt"
    export.write_bytes(_explicit())
    artifacts = _artifacts(tmp_path)
    artifacts.bioprobe_second.write_bytes(
        artifacts.bioprobe_second.read_bytes() + b"different-but-valid-zip-comment"
    )
    result = _test_result(tmp_path)
    parent = tmp_path / "evidence"
    parent.mkdir(mode=0o700)
    with pytest.raises(BioPipeError, match="reviewed format"):
        create_release_acceptance_evidence(
            repository=repository,
            output_directory=parent / "release-acceptance",
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            ci_run_id=CI_RUN_ID,
            environment_export=export,
            test_result=result,
            artifact_paths=artifacts,
        )

    skipped = tmp_path / "skipped-result.json"
    skipped.write_text(
        '{"errors":0,"failures":0,"skipped":1,"status":"passed","tests":3}\n',
        encoding="ascii",
    )
    with pytest.raises(BioPipeError, match="reviewed format"):
        create_release_acceptance_evidence(
            repository=repository,
            output_directory=parent / "release-acceptance",
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            ci_run_id=CI_RUN_ID,
            environment_export=export,
            test_result=skipped,
            artifact_paths=_artifacts(tmp_path / "fresh-artifacts"),
        )

    non_integral = tmp_path / "non-integral-result.json"
    non_integral.write_text(
        '{"errors":0.0,"failures":0,"skipped":0,"status":"passed","tests":3.0}\n',
        encoding="ascii",
    )
    with pytest.raises(BioPipeError, match="reviewed format"):
        create_release_acceptance_evidence(
            repository=repository,
            output_directory=parent / "release-acceptance",
            release_id=RELEASE_ID,
            created_at=CREATED_AT,
            ci_run_id=CI_RUN_ID,
            environment_export=export,
            test_result=non_integral,
            artifact_paths=_artifacts(tmp_path / "non-integral-artifacts"),
        )


def test_ci_evidence_rejects_release_id_for_a_different_controller_version(
    tmp_path: Path,
) -> None:
    repository, _commit = _repository(tmp_path)
    export = tmp_path / "native-export.txt"
    export.write_bytes(_explicit())
    parent = tmp_path / "evidence"
    parent.mkdir(mode=0o700)

    with pytest.raises(BioPipeError, match="reviewed format"):
        create_release_acceptance_evidence(
            repository=repository,
            output_directory=parent / "release-acceptance",
            release_id="9.9.9-rc1",
            created_at=CREATED_AT,
            ci_run_id=CI_RUN_ID,
            environment_export=export,
            test_result=_test_result(tmp_path),
            artifact_paths=_artifacts(tmp_path),
        )


def test_offline_verifier_rejects_tampering(tmp_path: Path) -> None:
    output, _commit = _create(tmp_path)
    manifest = output / "SHA256SUMS"
    payload = manifest.read_bytes()
    manifest.write_bytes((b"0" if payload[:1] != b"0" else b"1") + payload[1:])

    with pytest.raises(BioPipeError, match="reviewed format"):
        verify_release_acceptance_evidence(output)


def test_offline_verifier_rejects_an_intermediate_directory_symlink(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("directory symlink semantics differ on Windows")
    output, _commit = _create(tmp_path)
    link = tmp_path / "evidence-link"
    link.symlink_to(output.parent, target_is_directory=True)

    with pytest.raises(BioPipeError):
        verify_release_acceptance_evidence(link / output.name)


def test_junit_reducer_requires_three_passes_and_zero_skips(tmp_path: Path) -> None:
    passed = tmp_path / "passed.xml"
    passed.write_text(_junit_xml(), encoding="utf-8")
    assert junit.summarize_junit(passed) == {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "status": "passed",
        "tests": 3,
    }

    skipped = tmp_path / "skipped.xml"
    skipped.write_text(_junit_xml(third_child="<skipped />", skipped=1), encoding="utf-8")
    with pytest.raises(ValueError, match="NOT_ALL_PASSED"):
        junit.summarize_junit(skipped)

    lying_failure = tmp_path / "lying-failure.xml"
    lying_failure.write_text(_junit_xml(third_child="<failure />"), encoding="utf-8")
    with pytest.raises(ValueError, match="NOT_ALL_PASSED"):
        junit.summarize_junit(lying_failure)

    wrong_test = tmp_path / "wrong-test.xml"
    wrong_test.write_text(_junit_xml(third_name="test_not_reviewed"), encoding="utf-8")
    with pytest.raises(ValueError, match="NOT_ALL_PASSED"):
        junit.summarize_junit(wrong_test)


def test_junit_reducer_writes_only_fixed_create_only_json(tmp_path: Path) -> None:
    junit_path = tmp_path / "result.xml"
    junit_path.write_text(_junit_xml(), encoding="utf-8")
    output_parent = tmp_path / "private"
    output_parent.mkdir(mode=0o700)
    output = output_parent / "safe.json"

    assert junit.main(["--junit", str(junit_path), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="ascii")) == {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "status": "passed",
        "tests": 3,
    }
    assert str(tmp_path).encode() not in output.read_bytes()
    assert junit.main(["--junit", str(junit_path), "--output", str(output)]) == 2


def test_junit_reducer_rejects_an_intermediate_output_symlink(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("directory symlink semantics differ on Windows")
    junit_path = tmp_path / "result.xml"
    junit_path.write_text(_junit_xml(), encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    assert junit.main(["--junit", str(junit_path), "--output", str(link / "safe.json")]) == 2
    assert not (target / "safe.json").exists()
