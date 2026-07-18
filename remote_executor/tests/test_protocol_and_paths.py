from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import bioexec.config as config_module
from bioexec.config import AgentConfig, discover_config_path, load_config
from bioexec.errors import AgentFailure, ReturnCode
from bioexec.main import serve_once
from bioexec.paths import PathGuard
from bioexec.protocol import decode_json_line, parse_request

from .conftest import config_json, write_config


def _request(operation: str, payload: dict[str, object] | None = None) -> bytes:
    return (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": "request-1",
                "operation": operation,
                "payload": payload or {},
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def test_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(AgentFailure) as raised:
        decode_json_line(b'{"value":1,"value":2}')
    assert raised.value.code == "INVALID_JSON"


def test_unknown_operation_and_envelope_fields_are_rejected() -> None:
    with pytest.raises(AgentFailure) as raised:
        parse_request(
            {
                "protocol_version": "1.0",
                "request_id": "request-1",
                "operation": "exec",
                "payload": {},
            }
        )
    assert raised.value.return_code == ReturnCode.UNSUPPORTED_OPERATION
    with pytest.raises(AgentFailure):
        parse_request(
            {
                "protocol_version": "1.0",
                "request_id": "request-1",
                "operation": "health",
                "payload": {},
                "command": "id",
            }
        )


@pytest.mark.parametrize(
    "framing",
    [
        _request("health") + _request("health"),
        _request("health").rstrip(b"\n"),
        _request("health").replace(b"\n", b"\r\n"),
    ],
)
def test_service_requires_exactly_one_canonical_jsonl_frame(
    framing: bytes,
    agent_config: AgentConfig,
) -> None:
    response = serve_once(io.BytesIO(framing), agent_config)
    assert response["success"] is False
    assert response["error"]["code"] == "INVALID_JSONL_FRAME"


def test_service_rejects_unknown_health_payload_field(agent_config: AgentConfig) -> None:
    response = serve_once(io.BytesIO(_request("health", {"verbose": True})), agent_config)
    assert response["success"] is False
    assert response["error"]["code"] == "SCHEMA_ERROR"


def test_health_advertises_signed_abandon_operation(agent_config: AgentConfig) -> None:
    response = serve_once(io.BytesIO(_request("health")), agent_config)
    assert response["success"] is True
    assert response["result"]["operations"] == [
        "abandon",
        "deploy",
        "health",
        "preflight",
        "resume",
        "status",
        "submit",
    ]


def test_path_guard_rejects_outside_and_symlink_escape(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    guard = PathGuard()
    with (
        pytest.raises(AgentFailure) as outside,
        guard.open_regular(str(tmp_path / "outside.fastq"), agent_config.read_roots),
    ):
        pass
    assert outside.value.return_code == ReturnCode.PATH_OUTSIDE_ALLOWLIST
    target = tmp_path / "outside.fastq"
    target.write_bytes(b"synthetic\n")
    link = agent_config.read_roots[0].path / "link.fastq"
    link.symlink_to(target)
    with (
        pytest.raises(AgentFailure) as escaped,
        guard.open_regular(str(link), agent_config.read_roots),
    ):
        pass
    assert escaped.value.return_code == ReturnCode.SYMLINK_OR_ESCAPE


def test_config_rejects_symlink_and_group_writable_file(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    real = tmp_path / "config.json"
    write_config(real, config_json(agent_config))
    link = tmp_path / "config-link.json"
    link.symlink_to(real)
    with pytest.raises(AgentFailure):
        load_config(link)
    real.chmod(0o622)
    with pytest.raises(AgentFailure) as raised:
        load_config(real)
    assert raised.value.code == "CONFIG_INVALID"


def test_example_config_is_an_inert_fail_closed_template(tmp_path: Path) -> None:
    example = Path(__file__).parents[1] / "examples" / "config.json"
    value = json.loads(example.read_text(encoding="utf-8"))
    assert value["profile_hash"].startswith("REPLACE_")
    assert value["approval_hmac_key"].startswith("REPLACE_")
    assert value["nextflow_version"].startswith("REPLACE_")
    assert value["nextflow_jar_sha256"].startswith("REPLACE_")
    copied = tmp_path / "example.json"
    write_config(copied, value)

    with pytest.raises(AgentFailure) as raised:
        load_config(copied)

    assert raised.value.code == "CONFIG_INVALID"


def test_config_is_discovered_from_default_account_location_without_env(
    agent_config: AgentConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    default = tmp_path / ".config" / "bioexec" / "config.json"
    default.parent.mkdir(parents=True)
    write_config(default, config_json(agent_config))
    monkeypatch.delenv("BIOEXEC_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert discover_config_path() == default
    loaded = load_config()
    assert loaded.profile_hash == agent_config.profile_hash


def test_config_rejects_overlapping_role_roots(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    value = config_json(agent_config)
    value["work_roots"] = value["deploy_roots"]
    path = tmp_path / "overlap.json"
    write_config(path, value)
    with pytest.raises(AgentFailure) as raised:
        load_config(path)
    assert raised.value.code == "CONFIG_INVALID"


def test_config_rejects_group_writable_role_root(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    work = agent_config.work_roots[0].path
    work.chmod(0o770)
    path = tmp_path / "group-writable-root.json"
    write_config(path, config_json(agent_config))
    with pytest.raises(AgentFailure) as raised:
        load_config(path)
    assert raised.value.code == "CONFIG_INVALID"


def test_config_parent_walk_allows_sticky_anchor_but_rejects_plain_writable_parent(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir(mode=0o700)
    sticky.chmod(0o1777)
    accepted = sticky / "config.json"
    write_config(accepted, config_json(agent_config))
    assert load_config(accepted).profile_id == agent_config.profile_id

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o777)
    rejected = unsafe / "config.json"
    write_config(rejected, config_json(agent_config))
    with pytest.raises(AgentFailure) as raised:
        load_config(rejected)
    assert raised.value.code == "CONFIG_INVALID"


def test_config_rejects_executable_under_world_writable_parent(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "unsafe-bin"
    unsafe.mkdir(mode=0o700)
    docker = unsafe / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    unsafe.chmod(0o777)
    value = config_json(agent_config)
    value["executables"]["docker"] = str(docker)
    path = tmp_path / "unsafe-executable-parent.json"
    write_config(path, value)
    with pytest.raises(AgentFailure) as raised:
        load_config(path)
    assert raised.value.code == "CONFIG_INVALID"


def test_config_rejects_executable_parent_with_path_separator(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    ambiguous = tmp_path / "reviewed:split"
    ambiguous.mkdir(mode=0o700)
    docker = ambiguous / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    value = config_json(agent_config)
    value["executables"]["docker"] = str(docker)
    path = tmp_path / "ambiguous-path.json"
    write_config(path, value)
    with pytest.raises(AgentFailure) as raised:
        load_config(path)
    assert raised.value.code == "CONFIG_INVALID"


def test_config_rejects_file_owned_by_untrusted_uid(
    agent_config: AgentConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "untrusted-owner.json"
    write_config(path, config_json(agent_config))
    metadata = path.stat()
    monkeypatch.setattr(
        config_module.os,
        "fstat",
        lambda _descriptor: SimpleNamespace(
            st_mode=metadata.st_mode,
            st_size=metadata.st_size,
            st_uid=metadata.st_uid + 100_000,
        ),
    )
    with pytest.raises(AgentFailure) as raised:
        load_config(path)
    assert raised.value.code == "CONFIG_INVALID"


def test_config_rejects_writable_or_untrusted_executable(
    agent_config: AgentConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = config_json(agent_config)
    writable = Path(value["executables"]["docker"])
    writable.chmod(0o777)
    mode_path = tmp_path / "writable-executable.json"
    write_config(mode_path, value)
    with pytest.raises(AgentFailure) as mode_error:
        load_config(mode_path)
    assert mode_error.value.code == "CONFIG_INVALID"

    writable.chmod(0o755)
    owner_path = tmp_path / "owner-executable.json"
    write_config(owner_path, value)
    real_open = config_module._open_trusted_regular

    def substitute_owner(path: Path) -> tuple[int, object]:
        descriptor, metadata = real_open(path)
        if path == writable:
            return descriptor, SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=metadata.st_uid + 100_000,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_size=metadata.st_size,
            )
        return descriptor, metadata

    monkeypatch.setattr(config_module, "_open_trusted_regular", substitute_owner)
    with pytest.raises(AgentFailure) as owner_error:
        load_config(owner_path)
    assert owner_error.value.code == "CONFIG_INVALID"


def test_request_budget_is_enforced_before_parsing(agent_config: AgentConfig) -> None:
    oversized = b"{" + b"x" * agent_config.limits.max_request_bytes + b"\n"
    response = serve_once(io.BytesIO(oversized), agent_config)
    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED


def test_paths_with_shell_metacharacters_are_never_executed(
    agent_config: AgentConfig,
) -> None:
    name = "sample;touch SHOULD_NOT_EXIST.fastq"
    path = agent_config.read_roots[0].path / name
    path.write_bytes(b"synthetic\n")
    with PathGuard().open_regular(str(path), agent_config.read_roots) as (_fd, authorized, _stat):
        assert authorized.path.name == name
    assert not (Path.cwd() / "SHOULD_NOT_EXIST.fastq").exists()
