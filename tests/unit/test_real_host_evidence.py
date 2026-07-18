"""Functional contracts for sanitized operator real-host evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import fields, replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.real_host import (
    REAL_HOST_EVIDENCE_NAMES,
    create_real_host_acceptance_evidence,
    verify_real_host_acceptance_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = REPOSITORY_ROOT / "scripts" / "collect_real_host_evidence.py"
SUPPORT = REPOSITORY_ROOT / "tests" / "real_host_evidence_support.py"


def _load_support() -> ModuleType:
    module_name = "_easy_pipe_real_host_evidence_test_support"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, SUPPORT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_support = _load_support()
COMMIT = _support.COMMIT
CREATED_AT = _support.CREATED_AT
PRIVATE_SENTINEL = _support.PRIVATE_SENTINEL
RELEASE_ID = _support.RELEASE_ID
RealHostCase = _support.RealHostCase
build_real_host_case = _support.build_real_host_case


def _load_collector() -> ModuleType:
    spec = importlib.util.spec_from_file_location("test_real_host_collector", COLLECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create(case: RealHostCase, output: Path) -> dict[str, object]:
    return create_real_host_acceptance_evidence(
        repository=case.repository,
        candidate_evidence=case.candidate_evidence,
        output_directory=output,
        created_at=CREATED_AT,
        inputs=case.inputs,
    )


def _audit_events(case: RealHostCase) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in case.inputs.audit_final.read_text(encoding="utf-8").splitlines()
    ]


def _write_audit(case: RealHostCase, events: list[dict[str, Any]]) -> None:
    case.inputs.audit_final.write_text(
        "".join(
            json.dumps(
                event,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
            for event in events
        ),
        encoding="utf-8",
    )


def test_collector_argument_errors_do_not_echo_private_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    collector = _load_collector()
    private_argument = f"--unknown-{PRIVATE_SENTINEL}"

    with pytest.raises(SystemExit) as raised:
        collector.main(["create", private_argument, f"/private/{PRIVATE_SENTINEL}"])

    assert raised.value.code == 2
    streams = capsys.readouterr()
    assert PRIVATE_SENTINEL not in streams.out
    assert PRIVATE_SENTINEL not in streams.err


def test_collector_creates_strict_bundle_and_verifies_it_fully_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    output = case.output_parent / "real-host-evidence"
    collector = _load_collector()

    assert collector.main(case.create_arguments(output)) == 0
    create_streams = capsys.readouterr()
    assert create_streams.err == ""
    created = json.loads(create_streams.out)
    assert created == {
        "acceptance_status": "passed",
        "evidence_manifest_sha256": created["evidence_manifest_sha256"],
        "file_count": 2,
        "release_decision": "BLOCKED",
        "release_id": RELEASE_ID,
        "source_git_commit": COMMIT,
        "status": "real_host_acceptance_evidence_created_unreviewed",
    }
    assert set(path.name for path in output.iterdir()) == set(REAL_HOST_EVIDENCE_NAMES)

    summary = json.loads((output / "real-host-acceptance.json").read_text(encoding="utf-8"))
    assert summary["evidence_status"] == "OPERATOR_GENERATED_UNREVIEWED"
    assert summary["independent_review_status"] == "PENDING_INDEPENDENT_REVIEW"
    assert summary["release_decision"] == "BLOCKED"
    assert summary["synthetic_remote_only"] is True
    assert summary["real_ssh_exercised"] is True
    assert len(summary["artifacts"]) == 18

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline verification attempted an external binding")

    import biopipe.release_evidence.real_host as real_host

    monkeypatch.setattr(real_host, "verify_release_evidence", forbidden)
    monkeypatch.setattr(real_host, "resolve_clean_repository_commit", forbidden)
    monkeypatch.setattr(real_host, "validate_runtime_repository_binding", forbidden)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("HOME", str(tmp_path / "missing-private-home"))
    assert collector.main(["verify", "--directory", str(output)]) == 0
    verify_streams = capsys.readouterr()
    assert verify_streams.err == ""
    verified = json.loads(verify_streams.out)
    assert verified["status"] == "real_host_acceptance_evidence_verified_offline"
    assert verified["evidence_manifest_sha256"] == created["evidence_manifest_sha256"]


def test_create_is_deterministic_private_and_create_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    first = case.output_parent / "first"
    second = case.output_parent / "second"

    first_result = _create(case, first)
    second_result = _create(case, second)

    assert first_result == second_result
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }
    bundle = case.bundle_bytes(first)
    assert PRIVATE_SENTINEL.encode() not in bundle
    for field in fields(case.inputs):
        supplied = getattr(case.inputs, field.name)
        assert str(supplied).encode() not in bundle
        assert supplied.name.encode() not in bundle

    original = {path.name: path.read_bytes() for path in first.iterdir()}
    with pytest.raises(BioPipeError) as raised:
        _create(case, first)
    assert raised.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert original == {path.name: path.read_bytes() for path in first.iterdir()}


@pytest.mark.parametrize(
    ("role", "mutate", "reason"),
    [
        (
            "status_report",
            lambda value: value.__setitem__("run_id", "run-" + "e" * 32),
            "execution_report_binding",
        ),
        (
            "run_report",
            lambda value: value.__setitem__("project_hash", "e" * 64),
            "execution_report_binding",
        ),
    ],
)
def test_create_rejects_cross_record_binding_mismatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    mutate: Any,
    reason: str,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    case.rewrite_json(role, mutate)

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": reason}
    assert not (case.output_parent / "rejected").exists()


def test_create_rejects_out_of_order_audit_and_wrong_terminal_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ordered_case = build_real_host_case(tmp_path / "ordered", monkeypatch)
    ordered_lines = ordered_case.inputs.audit_final.read_bytes().splitlines(keepends=True)
    ordered_lines[1], ordered_lines[2] = ordered_lines[2], ordered_lines[1]
    ordered_case.inputs.audit_final.write_bytes(b"".join(ordered_lines))

    with pytest.raises(BioPipeError) as out_of_order:
        _create(ordered_case, ordered_case.output_parent / "rejected")
    assert out_of_order.value.context == {"reason": "audit_order"}

    terminal_case = build_real_host_case(tmp_path / "terminal", monkeypatch)
    payload = terminal_case.inputs.audit_final.read_bytes()
    return_code_hash = '"return_code":"' + hashlib.sha256(b"0").hexdigest() + '"'
    assert return_code_hash.encode() in payload
    terminal_case.inputs.audit_final.write_bytes(
        payload.replace(return_code_hash.encode(), b'"return_code":"' + b"f" * 64 + b'"')
    )

    with pytest.raises(BioPipeError) as terminal:
        _create(terminal_case, terminal_case.output_parent / "rejected")
    assert terminal.value.context == {"reason": "audit_terminal_binding"}


def test_create_allows_multiple_hash_bound_status_queries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    events = _audit_events(case)
    query_index = next(
        index for index, event in enumerate(events) if event["event_type"] == "RUN_STATUS_QUERIED"
    )
    repeated = dict(events[query_index])
    repeated["event_id"] = "00000000-0000-0000-0000-0000000000ff"
    repeated["timestamp"] = "2026-07-18T08:30:01.500000Z"
    events.insert(query_index + 1, repeated)
    _write_audit(case, events)

    result = _create(case, case.output_parent / "multiple-status-queries")

    assert result["status"] == "real_host_acceptance_evidence_created_unreviewed"


@pytest.mark.parametrize("event_type", ["REAL_DATA_APPROVED", "PIPELINE_DEPLOYED"])
def test_create_rejects_duplicate_singleton_audit_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_type: str,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    events = _audit_events(case)
    event_index = next(
        index for index, event in enumerate(events) if event["event_type"] == event_type
    )
    repeated = dict(events[event_index])
    repeated["event_id"] = "00000000-0000-0000-0000-0000000000fe"
    repeated["timestamp"] = str(repeated["timestamp"]).replace(":00Z", ":30Z")
    events.insert(event_index + 1, repeated)
    _write_audit(case, events)

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": "audit_sequence"}


def test_create_rejects_status_query_outside_the_terminal_query_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    events = _audit_events(case)
    query = next(event for event in events if event["event_type"] == "RUN_STATUS_QUERIED")
    submitted_index = next(
        index for index, event in enumerate(events) if event["event_type"] == "RUN_SUBMITTED"
    )
    misplaced = dict(query)
    misplaced["event_id"] = "00000000-0000-0000-0000-0000000000fd"
    misplaced["timestamp"] = "2026-07-18T08:20:03.500000Z"
    events.insert(submitted_index, misplaced)
    _write_audit(case, events)

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": "audit_sequence"}


def test_create_rejects_audit_events_after_evidence_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    events = _audit_events(case)
    events[-1]["timestamp"] = "2026-07-18T09:00:01Z"
    _write_audit(case, events)

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": "audit_time_binding"}


def test_create_binds_candidate_record_to_the_verified_manifest_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    candidate = case.candidate_evidence / "candidate.json"
    candidate.write_bytes(candidate.read_bytes().replace(b"\n", b" \n", 1))

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": "candidate_record_binding"}


def test_create_binds_multiqc_files_to_the_terminal_result_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    unbound_report = tmp_path / "unbound" / "multiqc_report.html"
    unbound_report.parent.mkdir()
    unbound_report.write_bytes(case.inputs.multiqc_report.read_bytes())
    case.inputs = replace(case.inputs, multiqc_report=unbound_report)

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": "multiqc_path_binding"}


@pytest.mark.parametrize(
    ("role", "payload", "reason"),
    [
        (
            "multiqc_report",
            b"<!doctype html><html><body>generic report</body></html>\n",
            "multiqc_report",
        ),
        ("multiqc_data", b'{"unrelated_nonempty_data":[{"count":1}]}\n', "multiqc_data"),
        ("multiqc_data", b'{"report_general_stats_data":{}}\n', "multiqc_data"),
    ],
)
def test_create_rejects_weak_multiqc_placeholders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    payload: bytes,
    reason: str,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    getattr(case.inputs, role).write_bytes(payload)

    with pytest.raises(BioPipeError) as raised:
        _create(case, case.output_parent / "rejected")

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": reason}


def test_offline_verify_rejects_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    output = case.output_parent / "evidence"
    _create(case, output)
    summary = output / "real-host-acceptance.json"
    summary.write_bytes(summary.read_bytes().replace(RELEASE_ID.encode(), b"9.9.9-rc9"))

    with pytest.raises(BioPipeError) as raised:
        verify_real_host_acceptance_evidence(output)

    assert raised.value.code is ErrorCode.VALIDATION_FAILED
    assert raised.value.context == {"reason": "bundle_checksum"}
