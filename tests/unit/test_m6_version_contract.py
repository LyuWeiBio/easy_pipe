"""Frozen release-version and CLI exit-code compatibility contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bioexec import __version__ as executor_version
from biopipe import __version__ as controller_version
from biopipe.cli.app import app
from biopipe.cli.common import ExitCode
from biopipe.compiler import __version__ as compiler_version
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.registry import load_default_registry
from biopipe.version import (
    CLI_CONTRACT_VERSION,
    COMPILER_VERSION,
    CONTROLLER_VERSION,
    MVP_SCHEMA_VERSION,
    PROBE_VERSION,
    REGISTRY_VERSION,
    REMOTE_EXECUTOR_VERSION,
)
from bioprobe import __version__ as probe_version

runner = CliRunner()


def test_release_versions_do_not_drift_across_distributions() -> None:
    assert controller_version == CONTROLLER_VERSION
    assert compiler_version == COMPILER_VERSION
    assert probe_version == PROBE_VERSION
    assert executor_version == REMOTE_EXECUTOR_VERSION
    assert load_default_registry().version == REGISTRY_VERSION


def test_version_json_is_complete_and_stable() -> None:
    result = runner.invoke(app, ["version", "--json"])

    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.stdout) == {
        "cli_contract_version": CLI_CONTRACT_VERSION,
        "compiler_version": COMPILER_VERSION,
        "controller_version": CONTROLLER_VERSION,
        "exit_codes": {
            "command_failed": int(ExitCode.COMMAND_FAILED),
            "success": int(ExitCode.SUCCESS),
        },
        "probe_version": PROBE_VERSION,
        "registry_version": REGISTRY_VERSION,
        "registry_version_expected": REGISTRY_VERSION,
        "remote_executor_version": REMOTE_EXECUTOR_VERSION,
        "schema_version": MVP_SCHEMA_VERSION,
    }


def test_controlled_cli_failures_use_the_frozen_nonzero_exit_code() -> None:
    result = runner.invoke(app, ["schema", "show", "NotAContract", "--json"])

    assert result.exit_code == ExitCode.COMMAND_FAILED
    assert json.loads(result.stderr)["error"]["code"] == "VALIDATION_FAILED"


def test_schema_cli_lists_shows_and_exports_the_same_v1_catalog(tmp_path: Path) -> None:
    listed = runner.invoke(app, ["schema", "list", "--json"])
    shown = runner.invoke(app, ["schema", "show", "PipelineSpec", "--json"])
    output = tmp_path / "v1"
    exported = runner.invoke(
        app,
        ["schema", "export", "--output", str(output), "--json"],
    )

    assert listed.exit_code == shown.exit_code == exported.exit_code == ExitCode.SUCCESS
    catalog = json.loads(listed.stdout)
    schema = json.loads(shown.stdout)
    export_result = json.loads(exported.stdout)
    assert catalog["schema_version"] == schema["x-biopipe-schema-version"] == "1.0"
    assert schema["$id"].endswith("/PipelineSpec.schema.json")
    assert export_result["catalog_sha256"] == catalog["catalog_sha256"]
    assert json.loads((output / "catalog.json").read_text(encoding="utf-8")) == catalog


def test_missing_installed_schema_resource_uses_stable_cli_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> dict[str, object]:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "A frozen schema resource is unavailable.",
        )

    monkeypatch.setattr("biopipe.cli.schema.schema_catalog", unavailable)

    result = runner.invoke(app, ["schema", "list", "--json"])

    assert result.exit_code == ExitCode.COMMAND_FAILED
    assert json.loads(result.stderr)["error"]["code"] == "ARTIFACT_READ_FAILED"
