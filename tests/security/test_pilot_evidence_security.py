"""Privacy, filesystem, and offline boundaries for internal-pilot evidence."""

from __future__ import annotations

import getpass
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import NoReturn

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.checksums import checksum_payloads
from biopipe.release_evidence.pilot import (
    PILOT_REPORT_NAME,
    PILOT_SUMMARY_NAME,
    create_pilot_evidence,
    verify_pilot_evidence,
)

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
bundle_bytes = support.bundle_bytes
create_arguments = support.create_arguments
incomplete_record = support.incomplete_record
json_bytes = support.json_bytes
patch_external_bindings = support.patch_external_bindings
ready_record = support.ready_record


def _forbidden(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("ambient identity, project crawling, subprocess, or network was used")


def _reseal(output: Path) -> None:
    payloads = {
        name: (output / name).read_bytes() for name in (PILOT_SUMMARY_NAME, PILOT_REPORT_NAME)
    }
    (output / "SHA256SUMS").write_bytes(checksum_payloads(payloads))


@pytest.mark.parametrize(
    "payload",
    [
        b'{"format_version":"1.0","format_version":"1.0"}\n',
        b'{"format_version":"1.0","count":NaN}\n',
        b"\xff\xfe\n",
        b"[]\n",
    ],
)
def test_malformed_json_is_rejected_before_publication_without_input_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    record_path = Path(arguments["sanitized_record"])
    record_path.write_bytes(payload + PRIVATE_SENTINEL.encode("ascii"))

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    serialized = raised.value.to_json()
    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert PRIVATE_SENTINEL not in serialized
    assert str(record_path) not in serialized
    assert not Path(arguments["output_directory"]).exists()


@pytest.mark.parametrize("invalid_count", [True, "3", 3.0, -1, 1_000_001])
def test_counts_are_strict_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_count: object,
) -> None:
    patch_external_bindings(monkeypatch)
    record = incomplete_record()
    case = record["cases"][0]
    case["state"] = "evidence_missing"
    case["observed_at"] = "2026-07-19T07:00:00Z"
    case["validation"] = {"status": "evidence_missing", "code": "EVIDENCE_MISSING"}
    case["scan_file_count"] = invalid_count
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert not Path(arguments["output_directory"]).exists()


@pytest.mark.parametrize(
    ("scope", "field"),
    [
        ("root", "format_version"),
        ("root", "collection_policy_version"),
        ("root", "data_boundary"),
        ("root", "controls_relaxed"),
        ("drill", "control_relaxed"),
    ],
)
def test_critical_safety_claims_must_be_explicit_in_operator_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    field: str,
) -> None:
    patch_external_bindings(monkeypatch)
    record = ready_record()
    target = record if scope == "root" else record["drills"][0]
    del target[field]
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert not Path(arguments["output_directory"]).exists()


def test_unknown_private_fields_and_values_never_reach_error_or_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    record = incomplete_record()
    record["cases"][0]["raw_log"] = (
        f"/Users/private/{PRIVATE_SENTINEL}.fastq Authorization: Bearer secret"
    )
    arguments = create_arguments(tmp_path / "case", record)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    serialized = raised.value.to_json()
    assert PRIVATE_SENTINEL not in serialized
    assert "Authorization" not in serialized
    assert not Path(arguments["output_directory"]).exists()


def test_oversize_input_is_rejected_before_json_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    record_path = Path(arguments["sanitized_record"])
    record_path.write_bytes(b"{" + b" " * (256 * 1024) + b"}")

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED
    assert not Path(arguments["output_directory"]).exists()


@pytest.mark.parametrize("kind", ["leaf_symlink", "intermediate_symlink", "fifo"])
def test_unsafe_input_paths_are_rejected_without_opening_a_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    original = Path(arguments["sanitized_record"])
    if kind == "leaf_symlink":
        linked = original.with_name("linked.json")
        linked.symlink_to(original)
        arguments["sanitized_record"] = linked
    elif kind == "intermediate_symlink":
        real = original.parent / "real-private"
        real.mkdir(mode=0o700)
        nested = real / "record.json"
        nested.write_bytes(original.read_bytes())
        alias = original.parent / "alias-private"
        alias.symlink_to(real, target_is_directory=True)
        arguments["sanitized_record"] = alias / "record.json"
    else:
        fifo = original.with_name("record.fifo")
        os.mkfifo(fifo, mode=0o600)
        arguments["sanitized_record"] = fifo

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED
    assert not Path(arguments["output_directory"]).exists()


def test_create_does_not_crawl_neighboring_private_material_or_use_ambient_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    private_neighbor = Path(arguments["sanitized_record"]).parent / "reports"
    private_neighbor.mkdir(mode=0o700)
    (private_neighbor / f"{PRIVATE_SENTINEL}.fastq").write_text(
        "@A001:private-read\nACGT\n+\n!!!!\n", encoding="ascii"
    )
    os.mkfifo(private_neighbor / "audit.fifo", mode=0o600)
    monkeypatch.setattr(os, "walk", _forbidden)
    monkeypatch.setattr(Path, "glob", _forbidden)
    monkeypatch.setattr(Path, "rglob", _forbidden)
    monkeypatch.setattr(socket, "gethostname", _forbidden)
    monkeypatch.setattr(getpass, "getuser", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setenv("BIOPIPE_APPROVAL_HMAC_KEY", PRIVATE_SENTINEL)
    monkeypatch.setenv("SSH_AUTH_SOCK", f"/private/{PRIVATE_SENTINEL}")

    create_pilot_evidence(**arguments)

    output = Path(arguments["output_directory"])
    assert PRIVATE_SENTINEL.encode("ascii") not in bundle_bytes(output)


def test_offline_verifier_uses_only_fixed_bundle_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    created = create_pilot_evidence(**arguments)
    output = Path(arguments["output_directory"])
    monkeypatch.setattr(os, "walk", _forbidden)
    monkeypatch.setattr(Path, "glob", _forbidden)
    monkeypatch.setattr(Path, "rglob", _forbidden)
    monkeypatch.setattr(socket, "gethostname", _forbidden)
    monkeypatch.setattr(getpass, "getuser", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(
        "biopipe.release_evidence.pilot.resolve_clean_repository_commit", _forbidden
    )
    monkeypatch.setattr("biopipe.release_evidence.pilot.verify_release_evidence", _forbidden)

    assert verify_pilot_evidence(output) == created


@pytest.mark.parametrize("mutation", ["extra", "missing", "symlink", "fifo"])
def test_offline_verifier_requires_exact_regular_file_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    create_pilot_evidence(**arguments)
    output = Path(arguments["output_directory"])
    if mutation == "extra":
        (output / "private.log").write_text(PRIVATE_SENTINEL, encoding="ascii")
    elif mutation == "missing":
        (output / PILOT_REPORT_NAME).unlink()
    elif mutation == "symlink":
        report = output / PILOT_REPORT_NAME
        payload = report.read_bytes()
        report.unlink()
        outside = output.parent / "outside.md"
        outside.write_bytes(payload)
        report.symlink_to(outside)
    else:
        report = output / PILOT_REPORT_NAME
        report.unlink()
        os.mkfifo(report, mode=0o600)

    with pytest.raises(BioPipeError) as raised:
        verify_pilot_evidence(output)

    assert raised.value.code == ErrorCode.ARTIFACT_READ_FAILED


def test_resealed_summary_cannot_upgrade_review_or_production_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    create_pilot_evidence(**arguments)
    output = Path(arguments["output_directory"])
    summary_path = output / PILOT_SUMMARY_NAME
    summary = json.loads(summary_path.read_text(encoding="ascii"))
    summary["milestone_decision"] = "APPROVED"
    summary["production_authorization"] = True
    summary_path.write_bytes(json_bytes(summary))
    _reseal(output)

    with pytest.raises(BioPipeError) as raised:
        verify_pilot_evidence(output)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "pilot_summary"}


def test_resealed_duplicate_nested_key_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    create_pilot_evidence(**arguments)
    output = Path(arguments["output_directory"])
    summary_path = output / PILOT_SUMMARY_NAME
    payload = summary_path.read_bytes()
    needle = b'    "pilot_id": "pilot-20260719-001",\n'
    assert payload.count(needle) == 1
    summary_path.write_bytes(payload.replace(needle, needle + needle))
    _reseal(output)

    with pytest.raises(BioPipeError) as raised:
        verify_pilot_evidence(output)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED


def test_group_writable_output_parent_is_rejected_and_left_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    output = Path(arguments["output_directory"])
    output.parent.chmod(0o770)

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not output.exists()
    assert list(output.parent.iterdir()) == []


@pytest.mark.parametrize("role", ["sanitized_record", "output_directory"])
def test_private_record_and_bundle_are_rejected_inside_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    repository = Path(arguments["repository"])
    if role == "sanitized_record":
        source = Path(arguments["sanitized_record"])
        nested = repository / "private-record.json"
        nested.write_bytes(source.read_bytes())
        arguments[role] = nested
    else:
        arguments[role] = repository / "pilot-review-draft"

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {
        "reason": "private_path_inside_repository"
    }
    assert not Path(arguments["output_directory"]).exists()


@pytest.mark.parametrize(
    "protected_role",
    ["candidate_evidence", "release_acceptance_evidence", "real_host_evidence"],
)
def test_output_cannot_mutate_a_sealed_source_evidence_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protected_role: str,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    protected = Path(arguments[protected_role])
    before = {path.name: path.read_bytes() for path in protected.iterdir() if path.is_file()}
    arguments["output_directory"] = protected / "pilot-review-draft"

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "private_path_role_overlap"}
    assert not Path(arguments["output_directory"]).exists()
    assert {
        path.name: path.read_bytes() for path in protected.iterdir() if path.is_file()
    } == before


@pytest.mark.parametrize("protected_role", ["repository", "candidate_evidence"])
def test_parent_traversal_cannot_bypass_protected_root_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protected_role: str,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    protected = Path(arguments[protected_role])
    lexical_output = protected / "nonexistent-component" / ".." / "pilot-review-draft"
    arguments["output_directory"] = lexical_output

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    expected_reason = (
        "private_path_inside_repository"
        if protected_role == "repository"
        else "private_path_role_overlap"
    )
    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": expected_reason}
    assert not (protected / "pilot-review-draft").exists()


@pytest.mark.parametrize("protected_role", ["repository", "candidate_evidence"])
def test_case_alias_cannot_bypass_protected_root_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protected_role: str,
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    protected = Path(arguments[protected_role])
    case_alias = protected.parent / protected.name.swapcase()
    arguments["output_directory"] = case_alias / "pilot-review-draft"

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    expected_reason = (
        "private_path_inside_repository"
        if protected_role == "repository"
        else "private_path_role_overlap"
    )
    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": expected_reason}
    assert not (protected / "pilot-review-draft").exists()


def test_double_leading_slash_cannot_alias_output_into_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    repository = Path(arguments["repository"])
    arguments["output_directory"] = Path(
        f"//{os.fspath(repository).lstrip('/')}/pilot-review-draft"
    )

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": "output_directory_path"}
    assert not (repository / "pilot-review-draft").exists()


@pytest.mark.parametrize("protected_role", ["repository", "candidate_evidence"])
def test_filesystem_alias_cannot_bypass_protected_root_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protected_role: str,
) -> None:
    data_volume = Path("/System/Volumes/Data")
    if not data_volume.is_dir():
        pytest.skip("macOS data-volume alias is unavailable")

    patch_external_bindings(monkeypatch)
    arguments = create_arguments(tmp_path / "case", incomplete_record())
    protected = Path(arguments[protected_role])
    try:
        alias = data_volume / protected.relative_to("/")
    except ValueError:
        pytest.skip("temporary directory is not rooted on the macOS data volume")
    try:
        aliases_same_directory = alias.is_dir() and os.path.samefile(alias, protected)
    except OSError:
        aliases_same_directory = False
    if not aliases_same_directory:
        pytest.skip("temporary directory has no macOS data-volume alias")
    arguments["output_directory"] = alias / "pilot-review-draft"

    with pytest.raises(BioPipeError) as raised:
        create_pilot_evidence(**arguments)

    expected_reason = (
        "private_path_inside_repository"
        if protected_role == "repository"
        else "private_path_role_overlap"
    )
    assert raised.value.code == ErrorCode.VALIDATION_FAILED
    assert raised.value.to_dict()["error"]["context"] == {"reason": expected_reason}
    assert not (protected / "pilot-review-draft").exists()


def test_cli_parser_and_failures_do_not_echo_private_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    collector = _load_module("_easy_pipe_internal_pilot_collector", COLLECTOR)
    with pytest.raises(SystemExit) as raised:
        collector.main(["create", "--sanitized-record", PRIVATE_SENTINEL])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert PRIVATE_SENTINEL not in captured.err
    assert PRIVATE_SENTINEL not in captured.out

    patch_external_bindings(monkeypatch)
    record = incomplete_record()
    record["message"] = PRIVATE_SENTINEL
    arguments = create_arguments(tmp_path / "case", record)
    exit_code = collector.main(
        [
            "create",
            "--repository",
            str(arguments["repository"]),
            "--candidate-evidence",
            str(arguments["candidate_evidence"]),
            "--release-acceptance-evidence",
            str(arguments["release_acceptance_evidence"]),
            "--real-host-evidence",
            str(arguments["real_host_evidence"]),
            "--sanitized-record",
            str(arguments["sanitized_record"]),
            "--output",
            str(arguments["output_directory"]),
            "--created-at",
            str(arguments["created_at"]),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert PRIVATE_SENTINEL not in captured.err
    assert PRIVATE_SENTINEL not in captured.out
    assert str(arguments["sanitized_record"]) not in captured.err
