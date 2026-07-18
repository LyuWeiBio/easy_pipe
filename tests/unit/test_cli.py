"""Smoke tests for the Typer M0 command skeleton."""

from __future__ import annotations

import subprocess
import sys

import pytest
from typer.testing import CliRunner

from biopipe.cli.app import app
from biopipe.cli import app as exported_app


runner = CliRunner()

EXPECTED_COMMANDS = (
    "source",
    "inspect",
    "manifest",
    "plan",
    "generate",
    "validate",
    "test",
    "preflight",
    "run",
)
EXPECTED_LEAF_COMMANDS = (
    ("source", "add"),
    ("source", "list"),
    ("source", "show"),
    ("source", "remove"),
    ("source", "verify"),
    ("manifest", "show"),
    ("manifest", "apply-overrides"),
)


def test_cli_package_reexports_app() -> None:
    result = runner.invoke(exported_app, ["--help"])

    assert result.exit_code == 0, result.output


def test_root_help_is_available() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0, result.output
    assert "Usage" in result.output
    for command in EXPECTED_COMMANDS:
        assert command in result.output


def test_python_module_entrypoint_help_is_available() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "biopipe", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "Usage" in result.stdout


@pytest.mark.parametrize("command", EXPECTED_COMMANDS)
def test_placeholder_subcommand_help_is_available(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage" in result.output


@pytest.mark.parametrize(
    "command_path",
    EXPECTED_LEAF_COMMANDS,
    ids=("-".join(command_path) for command_path in EXPECTED_LEAF_COMMANDS),
)
def test_placeholder_leaf_help_is_available(command_path: tuple[str, ...]) -> None:
    result = runner.invoke(app, [*command_path, "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage" in result.output


def test_version_is_available_without_a_command() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "0.1.0"
