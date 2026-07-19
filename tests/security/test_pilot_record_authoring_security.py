"""Privacy and filesystem boundaries for pilot-record authoring."""

from __future__ import annotations

import getpass
import importlib.util
import os
import socket
import stat
import subprocess
import sys
import traceback
import unicodedata
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn

import pytest

import biopipe.release_evidence.filesystem as evidence_filesystem
import biopipe.release_evidence.pilot as pilot
import biopipe.release_evidence.pilot_record as pilot_record
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.pilot import create_pilot_evidence
from biopipe.release_evidence.pilot_record import (
    create_unexecuted_pilot_record,
    validate_sanitized_pilot_record,
)
from biopipe.release_evidence.store import EvidenceBundleStore

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SUPPORT = REPOSITORY_ROOT / "tests" / "pilot_evidence_support.py"
COLLECTOR = REPOSITORY_ROOT / "scripts" / "collect_internal_pilot_evidence.py"


def _load_module(name: str, path: Path) -> ModuleType:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


support = _load_module("_easy_pipe_pilot_evidence_test_support", SUPPORT)
PRIVATE_SENTINEL = support.PRIVATE_SENTINEL


def _forbidden(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("Git, evidence authentication, identity, crawling, or network was used")


def _arguments(root: Path) -> dict[str, Any]:
    root.mkdir(mode=0o700)
    repository = root / "repository"
    repository.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    return {
        "repository": repository,
        "output_file": private / "pilot-record.json",
        "pilot_id": "pilot-20260719-001",
        "environment_id": "env-001",
        "recorded_at": support.RECORDED_AT,
        "release_id": support.RELEASE_ID,
        "source_git_commit": support.COMMIT,
        "candidate_manifest_sha256": support.CANDIDATE_MANIFEST,
        "release_acceptance_manifest_sha256": support.ACCEPTANCE_MANIFEST,
        "real_host_manifest_sha256": support.REAL_HOST_MANIFEST,
    }


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _swap_directories(left: Path, right: Path) -> None:
    parking = left.parent / "directory-swap-parking"
    left.rename(parking)
    right.rename(left)
    parking.rename(right)


def _add_macos_acl(path: Path, rule: str) -> None:
    subprocess.run(
        ["/bin/chmod", "+a", rule, os.fspath(path)],
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        ([], False),
        (["com.apple.provenance"], False),
        (["system.posix_acl_access"], True),
        (["system.posix_acl_default"], True),
        (["system.richacl"], True),
        (["system.nfs4_acl"], True),
    ],
)
def test_linux_acl_policy_checks_only_xattrs_that_are_present(
    monkeypatch: pytest.MonkeyPatch,
    names: list[str],
    expected: bool,
) -> None:
    monkeypatch.setattr(evidence_filesystem.sys, "platform", "linux")
    monkeypatch.setattr(
        evidence_filesystem.os,
        "listxattr",
        lambda _descriptor: names,
        raising=False,
    )

    assert evidence_filesystem.descriptor_has_extended_acl(7) is expected


@pytest.mark.parametrize(
    "payload",
    [
        b'{"outer":{"duplicate":1,"duplicate":2}}\n',
        b'{"value":NaN}\n',
        b'{"value":Infinity}\n',
        b'{"value":-Infinity}\n',
        b"\xff\xfe\n",
        b"[]\n",
        b'"scalar"\n',
        b'{"unterminated":\n',
        b"\xef\xbb\xbf{}\n",
        b"{} trailing\n",
    ],
)
def test_validator_rejects_malformed_json_without_input_echo(
    tmp_path: Path, payload: bytes
) -> None:
    arguments = _arguments(tmp_path / "case")
    record = Path(arguments["output_file"])
    _write_private(record, payload + PRIVATE_SENTINEL.encode("ascii"))

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=arguments["repository"],
            record_file=record,
        )

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert PRIVATE_SENTINEL not in raised.value.to_json()
    assert str(record) not in raised.value.to_json()
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert PRIVATE_SENTINEL not in "".join(traceback.format_exception(raised.value))


@pytest.mark.parametrize("shape", ["deep", "huge_integer"])
def test_validator_rejects_parser_resource_edges(tmp_path: Path, shape: str) -> None:
    arguments = _arguments(tmp_path / "case")
    record = Path(arguments["output_file"])
    if shape == "deep":
        payload = b'{"nested":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}\n"
    else:
        payload = b'{"integer":' + b"9" * 5000 + b"}\n"
    _write_private(record, payload)

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=arguments["repository"],
            record_file=record,
        )

    assert raised.value.code == ErrorCode.VALIDATION_FAILED


def test_unknown_private_field_never_reaches_error_output(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    value = support.incomplete_record()
    value["raw_log"] = f"/Users/private/{PRIVATE_SENTINEL}.fastq Authorization: Bearer secret"
    record = Path(arguments["output_file"])
    _write_private(record, support.json_bytes(value))

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=arguments["repository"],
            record_file=record,
        )

    serialized = raised.value.to_json()
    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert PRIVATE_SENTINEL not in serialized
    assert "Authorization" not in serialized
    assert str(record) not in serialized
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    formatted = "".join(traceback.format_exception(raised.value))
    assert PRIVATE_SENTINEL not in formatted
    assert "Authorization" not in formatted


@pytest.mark.parametrize(
    ("kind", "expected_code"),
    [
        ("empty", ErrorCode.ARTIFACT_READ_FAILED),
        ("oversize", ErrorCode.ARTIFACT_READ_FAILED),
        ("public_mode", ErrorCode.ARTIFACT_READ_FAILED),
        ("hardlink", ErrorCode.ARTIFACT_READ_FAILED),
        ("leaf_symlink", ErrorCode.ARTIFACT_READ_FAILED),
        ("intermediate_symlink", ErrorCode.ARTIFACT_READ_FAILED),
        ("fifo", ErrorCode.ARTIFACT_READ_FAILED),
        ("directory", ErrorCode.ARTIFACT_READ_FAILED),
    ],
)
def test_validator_requires_one_private_regular_no_follow_file(
    tmp_path: Path,
    kind: str,
    expected_code: ErrorCode,
) -> None:
    arguments = _arguments(tmp_path / "case")
    original = Path(arguments["output_file"])
    payload = support.json_bytes(support.incomplete_record())
    if kind == "empty":
        _write_private(original, b"")
    elif kind == "oversize":
        _write_private(original, b"{" + b" " * (256 * 1024) + b"}")
    elif kind == "public_mode":
        original.write_bytes(payload)
        original.chmod(0o644)
    elif kind == "hardlink":
        _write_private(original, payload)
        os.link(original, original.with_name("second-link.json"))
    elif kind == "leaf_symlink":
        target = original.with_name("target.json")
        _write_private(target, payload)
        original.symlink_to(target)
    elif kind == "intermediate_symlink":
        target_dir = original.parent / "real"
        target_dir.mkdir(mode=0o700)
        target = target_dir / "record.json"
        _write_private(target, payload)
        alias = original.parent / "alias"
        alias.symlink_to(target_dir, target_is_directory=True)
        original = alias / "record.json"
    elif kind == "fifo":
        os.mkfifo(original, mode=0o600)
    else:
        original.mkdir(mode=0o700)

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=arguments["repository"],
            record_file=original,
        )

    assert raised.value.code == expected_code


def test_validator_rejects_record_hardlinked_into_repository(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    record = Path(arguments["output_file"])
    _write_private(record, support.json_bytes(support.incomplete_record()))
    repository_link = Path(arguments["repository"]) / "same-record.json"
    os.link(record, repository_link)

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=arguments["repository"],
            record_file=record,
        )

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED
    assert record.stat(follow_symlinks=False).st_nlink == 2


def test_compiler_rejects_a_multi_link_sanitized_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    support.patch_external_bindings(monkeypatch)
    arguments = support.create_arguments(tmp_path / "case", support.incomplete_record())
    record = Path(arguments["sanitized_record"])
    os.link(record, record.with_name("second-sanitized-record.json"))

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED
    assert not Path(arguments["output_directory"]).exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_validator_rejects_a_private_mode_file_with_extended_acl(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    record = Path(arguments["output_file"])
    _write_private(record, support.json_bytes(support.incomplete_record()))
    _add_macos_acl(record, "everyone allow read,write")
    assert stat.S_IMODE(record.stat(follow_symlinks=False).st_mode) == 0o600

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=arguments["repository"],
            record_file=record,
        )

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_initializer_rejects_an_extended_acl_on_the_output_parent(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path / "case")
    output = Path(arguments["output_file"])
    _add_macos_acl(
        output.parent,
        "everyone allow read,write,execute,delete_child,file_inherit,directory_inherit",
    )
    assert stat.S_IMODE(output.parent.stat(follow_symlinks=False).st_mode) == 0o700

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not output.exists()
    assert not list(output.parent.glob(".*.biopipe-*"))


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_bundle_store_rechecks_file_acl_after_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    output = parent / "review-draft"
    original_rename = EvidenceBundleStore._rename_exclusive

    def add_acl_then_rename(parent_descriptor: int, source: str, destination: str) -> None:
        _add_macos_acl(parent / source / "record.json", "everyone allow read")
        original_rename(parent_descriptor, source, destination)

    monkeypatch.setattr(
        EvidenceBundleStore,
        "_rename_exclusive",
        staticmethod(add_acl_then_rename),
    )

    with pytest.raises(BioPipeError) as raised:
        EvidenceBundleStore(output).create({"record.json": b"private\n"})

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not output.exists()
    assert not list(parent.glob(".*.biopipe-*"))


def test_validator_fd_traversal_rejects_a_repository_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(tmp_path / "case")
    repository = Path(arguments["repository"])
    private = Path(arguments["output_file"]).parent
    external_record = Path(arguments["output_file"])
    _write_private(
        repository / external_record.name, support.json_bytes(support.incomplete_record())
    )
    original_read = pilot_record.read_bounded_regular

    def swapped_read(*args: object, **kwargs: object) -> bytes:
        _swap_directories(repository, private)
        try:
            return original_read(*args, **kwargs)
        finally:
            _swap_directories(repository, private)

    monkeypatch.setattr(pilot_record, "read_bounded_regular", swapped_read)

    with pytest.raises(BioPipeError) as raised:
        validate_sanitized_pilot_record(
            repository=repository,
            record_file=external_record,
        )

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED
    assert (repository / external_record.name).is_file()
    assert not external_record.exists()


def test_initializer_fd_traversal_does_not_publish_through_a_repository_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(tmp_path / "case")
    repository = Path(arguments["repository"])
    output = Path(arguments["output_file"])
    private = output.parent
    original_create = EvidenceBundleStore.create_file

    def swapped_create(*args: object, **kwargs: object) -> Path:
        _swap_directories(repository, private)
        try:
            return original_create(*args, **kwargs)
        finally:
            _swap_directories(repository, private)

    monkeypatch.setattr(EvidenceBundleStore, "create_file", staticmethod(swapped_create))

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not (repository / output.name).exists()
    assert not output.exists()


@pytest.mark.parametrize("kind", ["existing_symlink", "existing_fifo", "existing_directory"])
def test_initializer_never_replaces_an_existing_special_destination(
    tmp_path: Path, kind: str
) -> None:
    arguments = _arguments(tmp_path / "case")
    output = Path(arguments["output_file"])
    marker = output.with_name("marker.txt")
    _write_private(marker, b"keep\n")
    if kind == "existing_symlink":
        output.symlink_to(marker)
    elif kind == "existing_fifo":
        os.mkfifo(output, mode=0o600)
    else:
        output.mkdir(mode=0o700)

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert marker.read_bytes() == b"keep\n"
    assert not any(
        path.name.startswith(".pilot-record.json.biopipe-") for path in output.parent.iterdir()
    )


@pytest.mark.parametrize("kind", ["group_writable", "intermediate_symlink"])
def test_initializer_rejects_an_unsafe_output_parent(tmp_path: Path, kind: str) -> None:
    arguments = _arguments(tmp_path / "case")
    output = Path(arguments["output_file"])
    if kind == "group_writable":
        output.parent.chmod(0o770)
    else:
        real_parent = output.parent.with_name("real-private")
        real_parent.mkdir(mode=0o700)
        alias = output.parent.with_name("private-alias")
        alias.symlink_to(real_parent, target_is_directory=True)
        arguments["output_file"] = alias / output.name

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not Path(arguments["output_file"]).exists()


@pytest.mark.parametrize("operation", ["init", "validate"])
@pytest.mark.parametrize("alias_kind", ["direct", "parent", "casefold", "nfd", "double_slash"])
def test_repository_aliases_cannot_contain_private_records(
    tmp_path: Path,
    operation: str,
    alias_kind: str,
) -> None:
    arguments = _arguments(tmp_path / "case")
    repository = Path(arguments["repository"])
    if alias_kind == "direct":
        private_path = repository / "pilot-record.json"
    elif alias_kind == "parent":
        private_path = repository / "missing" / ".." / "pilot-record.json"
    elif alias_kind == "casefold":
        alias = repository.parent / repository.name.swapcase()
        private_path = alias / "pilot-record.json"
    elif alias_kind == "nfd":
        named_repository = repository.with_name("r\u00e9pository")
        repository.rename(named_repository)
        repository = named_repository
        arguments["repository"] = repository
        alias = repository.parent / unicodedata.normalize("NFD", repository.name)
        private_path = alias / "pilot-record.json"
    else:
        private_path = Path(f"//{os.fspath(repository).lstrip('/')}/pilot-record.json")

    if operation == "init":
        arguments["output_file"] = private_path
    else:
        actual_path = repository / "pilot-record.json"
        _write_private(actual_path, support.json_bytes(support.incomplete_record()))
        if alias_kind in {"direct", "parent"}:
            private_path = (
                actual_path
                if alias_kind == "direct"
                else repository / "missing" / ".." / actual_path.name
            )

    with pytest.raises(BioPipeError) as raised:
        if operation == "init":
            create_unexecuted_pilot_record(**arguments)
        else:
            validate_sanitized_pilot_record(
                repository=arguments["repository"],
                record_file=private_path,
            )

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    if operation == "init":
        assert not (repository / "pilot-record.json").exists()


@pytest.mark.parametrize("operation", ["init", "validate"])
def test_macos_filesystem_alias_cannot_enter_repository(tmp_path: Path, operation: str) -> None:
    data_volume = Path("/System/Volumes/Data")
    if not data_volume.is_dir():
        pytest.skip("macOS data-volume alias is unavailable")
    arguments = _arguments(tmp_path / "case")
    repository = Path(arguments["repository"])
    try:
        alias_repository = data_volume / repository.relative_to("/")
    except ValueError:
        pytest.skip("temporary directory is not rooted on the macOS data volume")
    try:
        same_directory = alias_repository.is_dir() and os.path.samefile(
            alias_repository, repository
        )
    except OSError:
        same_directory = False
    if not same_directory:
        pytest.skip("temporary directory has no macOS data-volume alias")
    alias_record = alias_repository / "pilot-record.json"
    if operation == "init":
        arguments["output_file"] = alias_record
    else:
        _write_private(
            repository / "pilot-record.json",
            support.json_bytes(support.incomplete_record()),
        )

    with pytest.raises(BioPipeError) as raised:
        if operation == "init":
            create_unexecuted_pilot_record(**arguments)
        else:
            validate_sanitized_pilot_record(
                repository=repository,
                record_file=alias_record,
            )

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    if operation == "init":
        assert not (repository / "pilot-record.json").exists()


@pytest.mark.parametrize("repository_kind", ["missing", "symlink"])
def test_repository_identity_must_be_a_real_directory(tmp_path: Path, repository_kind: str) -> None:
    arguments = _arguments(tmp_path / "case")
    repository = Path(arguments["repository"])
    if repository_kind == "missing":
        repository.rmdir()
    else:
        real = repository.with_name("real-repository")
        repository.rename(real)
        repository.symlink_to(real, target_is_directory=True)

    with pytest.raises(BioPipeError) as raised:
        create_unexecuted_pilot_record(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert not Path(arguments["output_file"]).exists()


def test_authoring_never_uses_git_evidence_network_identity_or_project_crawling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _arguments(tmp_path / "case")
    for name in (
        "resolve_clean_repository_commit",
        "validate_runtime_repository_binding",
        "verify_release_evidence",
        "verify_release_acceptance_evidence",
        "verify_real_host_acceptance_evidence",
    ):
        monkeypatch.setattr(pilot, name, _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(socket, "gethostname", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(getpass, "getuser", _forbidden)
    monkeypatch.setattr(os, "walk", _forbidden)
    monkeypatch.setattr(Path, "glob", _forbidden)
    monkeypatch.setattr(Path, "rglob", _forbidden)
    monkeypatch.setenv("BIOPIPE_APPROVAL_HMAC_KEY", PRIVATE_SENTINEL)
    monkeypatch.setenv("SSH_AUTH_SOCK", f"/private/{PRIVATE_SENTINEL}")

    initialized = create_unexecuted_pilot_record(**arguments)
    validated = validate_sanitized_pilot_record(
        repository=arguments["repository"],
        record_file=arguments["output_file"],
    )

    assert initialized == validated
    assert validated.source_evidence_authentication_status == "NOT_PERFORMED"
    assert validated.independent_review_status == "NOT_PERFORMED"
    assert validated.milestone_decision == "BLOCKED"
    assert validated.production_authorization is False
    assert PRIVATE_SENTINEL.encode("ascii") not in Path(arguments["output_file"]).read_bytes()


def test_cli_parser_and_validation_failures_do_not_echo_private_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    collector = _load_module("_easy_pipe_internal_pilot_collector", COLLECTOR)
    with pytest.raises(SystemExit) as raised:
        collector.main(["init-record", "--pilot-id", PRIVATE_SENTINEL])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert PRIVATE_SENTINEL not in captured.out
    assert PRIVATE_SENTINEL not in captured.err

    arguments = _arguments(tmp_path / "case")
    value = support.incomplete_record()
    value["private_message"] = PRIVATE_SENTINEL
    record = Path(arguments["output_file"])
    _write_private(record, support.json_bytes(value))
    exit_code = collector.main(
        [
            "validate-record",
            "--repository",
            str(arguments["repository"]),
            "--sanitized-record",
            str(record),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert PRIVATE_SENTINEL not in captured.out
    assert PRIVATE_SENTINEL not in captured.err
    assert str(record) not in captured.err
