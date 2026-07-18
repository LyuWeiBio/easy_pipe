"""M5 execution-profile and default-deny CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from biopipe.cli.app import app
from biopipe.execution.models import ExecutionProfile
from biopipe.io import read_model, write_model_atomic
from biopipe.registry import load_default_registry

runner = CliRunner()


def test_execution_profile_create_and_show_are_create_only(tmp_path: Path) -> None:
    lock = load_default_registry().software_lock(("fastqc_raw_v1", "multiqc_v1"))
    lock_path = tmp_path / "software.lock.yaml"
    profile_directory = tmp_path / "profiles"
    write_model_atomic(lock, lock_path)
    approval_key = tmp_path / "approval.key"
    approval_key.write_text("9" * 64 + "\n", encoding="ascii")
    approval_key.chmod(0o600)
    arguments = [
        "execution-profile",
        "create",
        "docker-local",
        "--source-host",
        "source-a",
        "--execution-host",
        "source-a",
        "--ssh-alias",
        "source-a",
        "--approval-key-id",
        "controller-1",
        "--approval-key-file",
        str(approval_key),
        "--software-lock",
        str(lock_path),
        "--output-dir",
        str(profile_directory),
        "--deploy-root",
        "/remote/deploy",
        "--work-root",
        "/remote/work",
        "--output-root",
        "/remote/results",
        "--cache-root",
        "/remote/cache",
        "--container-engine",
        "docker",
        "--json",
    ]

    created = runner.invoke(app, arguments)
    duplicate = runner.invoke(app, arguments)
    shown = runner.invoke(
        app,
        [
            "execution-profile",
            "show",
            "docker-local",
            "--profile-dir",
            str(profile_directory),
            "--json",
        ],
    )

    assert created.exit_code == 0
    payload = json.loads(created.stdout)
    profile_path = Path(payload["profile_path"])
    assert profile_path.name == "docker-local.json"
    profile = read_model(profile_path, ExecutionProfile)
    assert profile.runtime.executor == "local"
    assert profile.runtime.container_engine == "docker"
    assert set(profile.containers) == set(lock.components)
    assert duplicate.exit_code == 2
    assert json.loads(duplicate.stderr)["error"]["code"] == "EXECUTION_PROFILE_INVALID"
    assert shown.exit_code == 0
    assert json.loads(shown.stdout) == profile.model_dump(mode="json")


def test_run_cli_refuses_missing_real_data_approval_before_reading_project() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "/does/not/exist",
            "--execution-profile",
            "/does/not/exist.json",
            "--actor",
            "pytest-operator",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "APPROVAL_REQUIRED"


def test_m5_commands_are_real_help_surfaces_not_placeholders() -> None:
    root = runner.invoke(app, ["--help"])
    preflight = runner.invoke(app, ["preflight", "--help"])
    run = runner.invoke(app, ["run", "--help"])

    assert root.exit_code == preflight.exit_code == run.exit_code == 0
    assert "execution-profile" in root.stdout
    assert "--execution-profile" in preflight.stdout
    assert "--approve-real-data" in run.stdout
    assert "placeholder" not in (root.stdout + preflight.stdout + run.stdout).casefold()
