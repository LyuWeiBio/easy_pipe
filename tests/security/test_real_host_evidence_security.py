"""Privacy and filesystem boundaries for real-host acceptance evidence."""

from __future__ import annotations

import getpass
import importlib.util
import json
import os
import socket
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import NoReturn

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.checksums import checksum_payloads
from biopipe.release_evidence.real_host import (
    create_real_host_acceptance_evidence,
    verify_real_host_acceptance_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
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
CREATED_AT = _support.CREATED_AT
PRIVATE_SENTINEL = _support.PRIVATE_SENTINEL
RealHostCase = _support.RealHostCase
build_real_host_case = _support.build_real_host_case


def _create(case: RealHostCase, output: Path) -> dict[str, object]:
    return create_real_host_acceptance_evidence(
        repository=case.repository,
        candidate_evidence=case.candidate_evidence,
        output_directory=output,
        created_at=CREATED_AT,
        inputs=case.inputs,
    )


def test_private_inputs_and_ambient_identity_or_secrets_never_enter_evidence_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ambient = {
        "HOSTNAME": "ambient-private-host.internal",
        "USER": "ambient-private-user",
        "LOGNAME": "ambient-private-logname",
        "SSH_AUTH_SOCK": "/private/ssh-agent-sensitive.sock",
        "BIOPIPE_APPROVAL_HMAC_KEY": "ambient-approval-hmac-sensitive-value",
        "AWS_SECRET_ACCESS_KEY": "ambient-cloud-secret-value",
        "SAMPLE_NAME": "ambient-patient-sample-name",
        "RAWDATA_PATH": "/srv/private/patient/rawdata",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)

    def forbidden_identity_lookup() -> NoReturn:
        raise AssertionError("ambient identity lookup is forbidden")

    monkeypatch.setattr(socket, "gethostname", forbidden_identity_lookup)
    monkeypatch.setattr(getpass, "getuser", forbidden_identity_lookup)
    case = build_real_host_case(tmp_path, monkeypatch)
    output = case.output_parent / "evidence"

    result = _create(case, output)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    streams = capsys.readouterr()
    combined = (
        streams.out.encode()
        + streams.err.encode()
        + b"".join(path.read_bytes() for path in output.iterdir())
    )

    assert PRIVATE_SENTINEL.encode() not in combined
    for value in ambient.values():
        assert value.encode() not in combined
    for field_name in case.inputs.__dataclass_fields__:
        path = getattr(case.inputs, field_name)
        assert os.fsencode(path) not in combined
        assert path.name.encode() not in combined


@pytest.mark.parametrize("unsafe_kind", ["leaf_symlink", "intermediate_symlink", "fifo"])
def test_create_rejects_unsafe_private_input_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    original = case.inputs.validation_report
    unsafe_root = tmp_path / f"unsafe-{PRIVATE_SENTINEL}"
    unsafe_root.mkdir()
    if unsafe_kind == "leaf_symlink":
        unsafe = unsafe_root / "linked-validation.json"
        unsafe.symlink_to(original)
    elif unsafe_kind == "intermediate_symlink":
        target = unsafe_root / "actual"
        target.mkdir()
        target_file = target / "validation.json"
        target_file.write_bytes(original.read_bytes())
        linked = unsafe_root / "linked-directory"
        linked.symlink_to(target, target_is_directory=True)
        unsafe = linked / target_file.name
    else:
        unsafe = unsafe_root / "validation.fifo"
        os.mkfifo(unsafe)
    selected_inputs = replace(case.inputs, validation_report=unsafe)
    output = case.output_parent / "must-not-exist"

    with pytest.raises(BioPipeError) as raised:
        create_real_host_acceptance_evidence(
            repository=case.repository,
            candidate_evidence=case.candidate_evidence,
            output_directory=output,
            created_at=CREATED_AT,
            inputs=selected_inputs,
        )

    assert raised.value.code is ErrorCode.ARTIFACT_READ_FAILED
    assert raised.value.context == {"resource_role": "validation_report"}
    assert PRIVATE_SENTINEL not in raised.value.to_json()
    assert str(unsafe) not in raised.value.to_json()
    assert not output.exists()


@pytest.mark.parametrize("unsafe_kind", ["leaf_symlink", "fifo", "directory_symlink"])
def test_offline_verify_rejects_unsafe_bundle_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    case = build_real_host_case(tmp_path, monkeypatch)
    output = case.output_parent / "evidence"
    _create(case, output)
    selected = output
    if unsafe_kind == "directory_symlink":
        selected = case.output_parent / "linked-evidence"
        selected.symlink_to(output, target_is_directory=True)
    else:
        summary = output / "real-host-acceptance.json"
        original = output / "original-summary.private"
        summary.rename(original)
        if unsafe_kind == "leaf_symlink":
            summary.symlink_to(original)
        else:
            os.mkfifo(summary)

    with pytest.raises(BioPipeError) as raised:
        verify_real_host_acceptance_evidence(selected)

    assert raised.value.code is ErrorCode.ARTIFACT_READ_FAILED
    assert PRIVATE_SENTINEL not in raised.value.to_json()


def test_duplicate_json_keys_are_rejected_on_create_and_offline_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_case = build_real_host_case(tmp_path / "create", monkeypatch)
    create_case.inputs.validation_report.write_bytes(
        b'{"report_version":"1.0","report_version":"1.0"}\n'
    )

    with pytest.raises(BioPipeError) as create_error:
        _create(create_case, create_case.output_parent / "rejected")
    assert create_error.value.code is ErrorCode.VALIDATION_FAILED
    assert create_error.value.context == {"reason": "validation_report"}

    verify_case = build_real_host_case(tmp_path / "verify", monkeypatch)
    output = verify_case.output_parent / "evidence"
    _create(verify_case, output)
    summary_path = output / "real-host-acceptance.json"
    original = summary_path.read_bytes()
    duplicate = original.replace(
        b'{\n  "acceptance_format_version": "1.0",',
        b'{\n  "acceptance_format_version": "1.0",\n  "acceptance_format_version": "1.0",',
        1,
    )
    assert duplicate != original
    summary_path.write_bytes(duplicate)
    (output / "SHA256SUMS").write_bytes(checksum_payloads({"real-host-acceptance.json": duplicate}))

    with pytest.raises(BioPipeError) as verify_error:
        verify_real_host_acceptance_evidence(output)
    assert verify_error.value.code is ErrorCode.VALIDATION_FAILED
    assert verify_error.value.context == {"reason": "real_host_acceptance"}
