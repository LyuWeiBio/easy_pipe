"""M5 authenticated controller-attestation tests."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import pytest

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalSigner,
    ContainerArtifact,
    ExecutionProfile,
    LocalExecutionRuntime,
)
from biopipe.execution.signing import canonical_attestation_bytes, sign_run_payload


def _profile(key_file: Path) -> ExecutionProfile:
    return ExecutionProfile(
        profile_id="remote-local",
        source_host="source-a",
        execution_host="source-a",
        ssh_alias="source-a",
        approval_signer=ApprovalSigner(
            key_id="controller-1",
            key_file=str(key_file),
        ),
        allowed_roots=AllowedExecutionRoots(
            deploy=("/remote/deploy",),
            work=("/remote/work",),
            output=("/remote/results",),
            cache=("/remote/cache",),
        ),
        runtime=LocalExecutionRuntime(container_engine="docker"),
        containers={
            "fastqc": ContainerArtifact(
                image="quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
                digest=f"sha256:{'a' * 64}",
            )
        },
    )


def test_run_attestation_is_canonical_bound_and_does_not_mutate_input(tmp_path: Path) -> None:
    key_file = tmp_path / "approval.key"
    key_file.write_text("9" * 64 + "\n", encoding="ascii")
    key_file.chmod(0o600)
    payload = {
        "run_id": "run-" + "1" * 32,
        "approval": {"approved": True, "actor": "operator-一"},
    }

    signed = sign_run_payload(_profile(key_file), "submit", payload)

    assert payload == {
        "run_id": "run-" + "1" * 32,
        "approval": {"approved": True, "actor": "operator-一"},
    }
    unsigned = {
        **signed,
        "approval": {key: value for key, value in signed["approval"].items() if key != "signature"},
    }
    expected = hmac.new(
        bytes.fromhex("9" * 64),
        canonical_attestation_bytes("submit", unsigned),
        hashlib.sha256,
    ).hexdigest()
    assert signed["approval"]["key_id"] == "controller-1"
    assert signed["approval"]["signature"] == expected
    assert sign_run_payload(_profile(key_file), "resume", payload) != signed


@pytest.mark.parametrize("mode", [0o644, 0o660])
def test_run_attestation_rejects_non_private_key_permissions(tmp_path: Path, mode: int) -> None:
    key_file = tmp_path / "approval.key"
    key_file.write_text("9" * 64 + "\n", encoding="ascii")
    key_file.chmod(mode)

    with pytest.raises(BioPipeError) as exc_info:
        sign_run_payload(_profile(key_file), "submit", {"approval": {"approved": True}})

    assert exc_info.value.code is ErrorCode.APPROVAL_REQUIRED
    assert exc_info.value.context == {"key_id": "controller-1"}
    assert str(key_file) not in exc_info.value.to_json()


def test_run_attestation_rejects_symlink_key(tmp_path: Path) -> None:
    actual = tmp_path / "actual.key"
    actual.write_text("9" * 64 + "\n", encoding="ascii")
    actual.chmod(0o600)
    linked = tmp_path / "linked.key"
    linked.symlink_to(actual)

    with pytest.raises(BioPipeError) as exc_info:
        sign_run_payload(_profile(linked), "submit", {"approval": {"approved": True}})

    assert exc_info.value.code is ErrorCode.APPROVAL_REQUIRED


def test_deploy_attestation_is_signed_and_operation_bound(tmp_path: Path) -> None:
    """M-C: deploy payloads carry a controller attestation like submit/resume/abandon."""
    key_file = tmp_path / "approval.key"
    key_file.write_text("9" * 64 + "\n", encoding="ascii")
    key_file.chmod(0o600)
    payload = {
        "deployment_id": "deployment-1",
        "preflight_id": "preflight-1",
        "profile_id": "remote-local",
        "profile_hash": "a" * 64,
        "project_hash": "b" * 64,
        "bundle_hash": "c" * 64,
        "deployment_dir": "/remote/deploy/deployment-1",
        "files": [{"path": "main.nf", "sha256": "d" * 64, "size": 12}],
        "approval": {},
    }

    signed = sign_run_payload(_profile(key_file), "deploy", payload)

    # The input is not mutated and the approval carries key_id + signature.
    assert payload["approval"] == {}
    assert signed["approval"]["key_id"] == "controller-1"
    signature = signed["approval"]["signature"]
    assert len(signature) == 64
    unsigned = {
        **signed,
        "approval": {key: value for key, value in signed["approval"].items() if key != "signature"},
    }
    expected = hmac.new(
        bytes.fromhex("9" * 64),
        canonical_attestation_bytes("deploy", unsigned),
        hashlib.sha256,
    ).hexdigest()
    assert signature == expected
    # The attestation is bound to the operation: a deploy envelope is not a
    # valid submit envelope and vice versa.
    assert canonical_attestation_bytes("deploy", unsigned) != canonical_attestation_bytes(
        "submit", unsigned
    )
