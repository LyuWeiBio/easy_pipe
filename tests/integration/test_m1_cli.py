"""CLI integration tests for M1 source management and metadata inspection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from biopipe.cli.app import app
from biopipe.models import ProbeResponse, SourceProfile
from biopipe.sources import SourceRegistry

runner = CliRunner()


def _profile() -> SourceProfile:
    return SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )


def _success_response(request_id: str, result: dict[str, Any]) -> ProbeResponse:
    return ProbeResponse(
        request_id=request_id,
        success=True,
        return_code=0,
        result=result,
    )


def test_source_cli_add_list_show_remove_round_trip(tmp_path: Path) -> None:
    config_dir = tmp_path / "controller"
    common = ["--config-dir", str(config_dir), "--json"]

    added = runner.invoke(
        app,
        [
            "source",
            "add",
            "synthetic-source",
            "--host",
            "synthetic-host",
            "--allowed-root",
            "/srv/synthetic-raw",
            *common,
        ],
    )
    assert added.exit_code == 0, added.output
    assert json.loads(added.stdout)["source_id"] == "synthetic-source"

    listed = runner.invoke(app, ["source", "list", *common])
    assert listed.exit_code == 0, listed.output
    assert [item["source_id"] for item in json.loads(listed.stdout)] == ["synthetic-source"]

    shown = runner.invoke(app, ["source", "show", "synthetic-source", *common])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.stdout)["ssh_alias"] == "synthetic-host"

    removed = runner.invoke(app, ["source", "remove", "synthetic-source", *common])
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.stdout)["status"] == "removed"
    assert SourceRegistry(config_dir / "sources").list() == []


def test_source_verify_uses_fixed_health_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "controller"
    SourceRegistry(config_dir / "sources").add(_profile())
    calls: list[tuple[str, str]] = []

    class FakeClient:
        def __init__(self, **limits: object) -> None:
            assert limits["max_stdout_bytes"] == 10 * 1024 * 1024
            assert limits["max_stderr_bytes"] == 4096

        def verify(self, profile: SourceProfile) -> ProbeResponse:
            calls.append(("verify", profile.source_id))
            return _success_response("verify-001", {"status": "ok"})

    monkeypatch.setattr("biopipe.cli.source.OpenSSHProbeClient", FakeClient)

    result = runner.invoke(
        app,
        [
            "source",
            "verify",
            "synthetic-source",
            "--config-dir",
            str(config_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["result"]["status"] == "ok"
    assert calls == [("verify", "synthetic-source")]


def test_inspect_cli_writes_metadata_response_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "controller"
    SourceRegistry(config_dir / "sources").add(_profile())
    output = tmp_path / "inspection.json"
    calls: list[tuple[str, str]] = []

    class FakeClient:
        def __init__(self, **limits: object) -> None:
            assert limits

        def list_tree(self, profile: SourceProfile, root: str) -> ProbeResponse:
            calls.append((profile.source_id, root))
            return _success_response(
                "tree-001",
                {
                    "operation": "list_tree",
                    "root": root,
                    "entries": [],
                    "entry_count": 0,
                },
            )

    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", FakeClient)

    result = runner.invoke(
        app,
        [
            "inspect",
            "synthetic-source:/srv/synthetic-raw/run-001",
            "--policy",
            "metadata-only",
            "--output",
            str(output),
            "--config-dir",
            str(config_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [("synthetic-source", "/srv/synthetic-raw/run-001")]
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(result.stdout)
    assert list(tmp_path.glob(".inspection.json.*.tmp")) == []


def test_inspect_cli_rejects_unknown_policy_without_contacting_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForbiddenClient:
        def __init__(self, **limits: object) -> None:
            raise AssertionError("probe client must not be constructed")

    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", ForbiddenClient)

    result = runner.invoke(
        app,
        [
            "inspect",
            "synthetic-source:/srv/synthetic-raw",
            "--policy",
            "integrity-check",
            "--config-dir",
            str(tmp_path),
            "--json",
        ],
    )

    assert result.exit_code == 2
    error = json.loads(result.stderr)
    assert error["error"]["code"] == "VALIDATION_FAILED"
