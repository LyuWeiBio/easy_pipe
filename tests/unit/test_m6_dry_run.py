"""M6 dry-run guarantees for every controller write or remote surface."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from typer.testing import CliRunner, Result

from biopipe.cli.app import app
from biopipe.models import SourceProfile
from biopipe.registry import load_default_registry
from biopipe.validation import ValidationReport

runner = CliRunner()


def _forbidden(*_args: object, **_kwargs: object) -> Any:
    raise AssertionError("dry-run reached a forbidden side-effect boundary")


def _valid_static_report(project: Path) -> ValidationReport:
    return ValidationReport(
        project_directory=str(project.absolute()),
        status="valid",
        checked_artifacts=[],
        artifact_hashes={},
        findings=[],
    )


def _assert_dry_run(result: Result) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    payload = cast(dict[str, Any], json.loads(result.stdout))
    assert payload["dry_run"] is True
    assert payload["side_effects_performed"] is False
    return payload


def test_source_add_dry_run_does_not_create_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("biopipe.cli.source.SourceRegistry.add", _forbidden)
    config = tmp_path / "controller"

    result = runner.invoke(
        app,
        [
            "source",
            "add",
            "synthetic-source",
            "--host",
            "synthetic-host",
            "--allowed-root",
            "/srv/synthetic-raw",
            "--config-dir",
            str(config),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == "would_add"
    assert not config.exists()


@pytest.mark.parametrize(
    ("command", "status", "remote"),
    [
        ("remove", "would_remove", []),
        ("verify", "would_verify", ["probe.health"]),
    ],
)
def test_existing_source_dry_runs_neither_mutate_nor_contact_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    status: str,
    remote: list[str],
) -> None:
    profile = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )
    monkeypatch.setattr("biopipe.cli.source.SourceRegistry.get", lambda *_args: profile)
    monkeypatch.setattr("biopipe.cli.source.SourceRegistry.remove", _forbidden)
    monkeypatch.setattr("biopipe.cli.source.OpenSSHProbeClient", _forbidden)
    config = tmp_path / "controller"

    result = runner.invoke(
        app,
        [
            "source",
            command,
            "synthetic-source",
            "--config-dir",
            str(config),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == status
    assert payload["remote_operations"] == remote
    assert not config.exists()


def test_inspect_dry_run_never_constructs_probe_client_or_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )
    monkeypatch.setattr("biopipe.cli.inspect.SourceRegistry.get", lambda *_args: profile)
    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", _forbidden)
    output = tmp_path / "artifacts" / "dataset.json"

    result = runner.invoke(
        app,
        [
            "inspect",
            "synthetic-source:/srv/synthetic-raw",
            "--policy",
            "format-summary",
            "--output",
            str(output),
            "--config-dir",
            str(tmp_path / "controller"),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["remote_operations"] == [
        "probe.detect_formats",
        "probe.list_tree",
        "probe.summarize_fastq",
    ]
    assert not output.parent.exists()


@pytest.mark.parametrize("root", ["relative/path", "/srv/outside-allowlist"])
def test_inspect_dry_run_rejects_invalid_or_out_of_scope_root_before_ssh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root: str,
) -> None:
    profile = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )
    monkeypatch.setattr("biopipe.cli.inspect.SourceRegistry.get", lambda *_args: profile)
    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", _forbidden)

    result = runner.invoke(
        app,
        [
            "inspect",
            f"synthetic-source:{root}",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "VALIDATION_FAILED"


def test_manifest_override_dry_run_resolves_in_memory_without_bundle_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = SimpleNamespace(
        errors=[],
        integrity=SimpleNamespace(manifest_sha256="a" * 64),
    )
    monkeypatch.setattr("biopipe.cli.manifest.read_model", lambda *_args: object())
    monkeypatch.setattr("biopipe.cli.manifest.require_valid_manifest", lambda value: value)
    monkeypatch.setattr(
        "biopipe.cli.manifest.apply_overrides",
        lambda *_args: SimpleNamespace(resolved_manifest=resolved, diff=object()),
    )
    monkeypatch.setattr("biopipe.cli.manifest.sanitize_manifest", lambda *_args: object())
    monkeypatch.setattr("biopipe.cli.manifest.render_samplesheet", lambda *_args: "sample\n")
    monkeypatch.setattr("biopipe.cli.manifest.ManifestArtifactStore.create_bundle", _forbidden)
    destination = tmp_path / "resolved"
    manifest_path = tmp_path / "manifest.json"
    overrides_path = tmp_path / "overrides.json"
    manifest_path.write_text("{}\n", encoding="utf-8")
    overrides_path.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "manifest",
            "apply-overrides",
            str(manifest_path),
            "--overrides",
            str(overrides_path),
            "--output-dir",
            str(destination),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not destination.exists()


def test_plan_dry_run_does_not_create_planning_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = SimpleNamespace(source=SimpleNamespace(root="/srv/synthetic-raw"))
    planned = SimpleNamespace(
        component_ids=("fastqc_raw_v1", "multiqc_v1"),
        registry_version="1.0.0",
    )
    monkeypatch.setattr("biopipe.cli.plan.read_model", lambda *_args: manifest)
    monkeypatch.setattr("biopipe.cli.plan.plan_fastq_qc", lambda *_args: planned)
    monkeypatch.setattr("biopipe.cli.plan._create_plan_bundle", _forbidden)
    output = tmp_path / "planning" / "pipeline.spec.yaml"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "plan",
            "--manifest",
            str(manifest_path),
            "--output",
            str(output),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not output.parent.exists()


def test_generate_dry_run_does_not_render_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planned = SimpleNamespace(
        component_ids=("fastqc_raw_v1", "multiqc_v1"),
        registry_version="1.0.0",
    )
    monkeypatch.setattr("biopipe.cli.generate.read_model", lambda *_args: object())
    monkeypatch.setattr(
        "biopipe.cli.generate.reconstruct_planned_pipeline",
        lambda *_args, **_kwargs: planned,
    )
    monkeypatch.setattr("biopipe.cli.generate.require_valid_manifest", lambda *_args: None)
    monkeypatch.setattr("biopipe.cli.generate.compile_nextflow_project", _forbidden)
    output = tmp_path / "generated"
    spec_path = tmp_path / "pipeline.spec.yaml"
    spec_path.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "generate",
            "--spec",
            str(spec_path),
            "--output",
            str(output),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not output.exists()


@pytest.mark.parametrize("command", ["validate", "test"])
def test_workflow_check_dry_runs_skip_external_tools_and_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    project = tmp_path / "generated"
    target = f"biopipe.cli.{command}"
    monkeypatch.setattr(
        f"{target}.validate_generated_project",
        lambda *_args, **_kwargs: _valid_static_report(project),
    )
    monkeypatch.setattr(f"{target}.WorkflowTestRunner", _forbidden)
    monkeypatch.setattr(f"{target}.write_project_report_atomic", _forbidden)

    result = runner.invoke(app, [command, str(project), "--dry-run", "--json"])

    _assert_dry_run(result)
    assert not project.exists()


def test_execution_profile_dry_run_never_reads_key_or_registers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    software_lock = load_default_registry().software_lock(("fastqc_raw_v1", "multiqc_v1"))
    monkeypatch.setattr("biopipe.cli.execution_profile.read_model", lambda *_args: software_lock)
    monkeypatch.setattr("biopipe.cli.execution_profile.validate_approval_key", _forbidden)
    monkeypatch.setattr(
        "biopipe.cli.execution_profile.ExecutionProfileRegistry.register",
        _forbidden,
    )
    output = tmp_path / "profiles"

    result = runner.invoke(
        app,
        [
            "execution-profile",
            "create",
            "local-docker",
            "--source-host",
            "source-a",
            "--execution-host",
            "source-a",
            "--ssh-alias",
            "source-a",
            "--software-lock",
            str(tmp_path / "software.lock.yaml"),
            "--output-dir",
            str(output),
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
            "--approval-key-id",
            "controller-1",
            "--approval-key-file",
            str(tmp_path / "missing.key"),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not output.exists()


def test_preflight_dry_run_never_contacts_executor_or_writes_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    monkeypatch.setattr(
        "biopipe.cli.preflight.read_model",
        lambda *_args: SimpleNamespace(profile_id="local-docker"),
    )
    monkeypatch.setattr(
        "biopipe.cli.preflight.validate_generated_project",
        lambda *_args, **_kwargs: _valid_static_report(project),
    )
    monkeypatch.setattr("biopipe.cli.preflight.run_preflight", _forbidden)

    result = runner.invoke(
        app,
        [
            "preflight",
            str(project),
            "--execution-profile",
            str(tmp_path / "profile.json"),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["remote_operations"] == ["executor.preflight"]
    assert not project.exists()


@pytest.mark.parametrize(
    ("mode_options", "expected_remote"),
    [
        ([], ["executor.deploy", "executor.submit"]),
        (["--resume", "run-" + "1" * 32], ["executor.resume"]),
        (["--status", "run-" + "2" * 32], ["executor.status"]),
        (["--abandon-pending", "run-" + "3" * 32], ["executor.abandon"]),
    ],
)
def test_run_dry_run_returns_before_keys_signing_deployment_and_ssh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode_options: list[str],
    expected_remote: list[str],
) -> None:
    monkeypatch.setattr("biopipe.cli.run.submit_approved_run", _forbidden)
    monkeypatch.setattr("biopipe.cli.run.query_run_status", _forbidden)
    monkeypatch.setattr("biopipe.cli.run.abandon_pending_run", _forbidden)
    project = tmp_path / "does-not-exist"

    result = runner.invoke(
        app,
        [
            "run",
            str(project),
            "--execution-profile",
            str(tmp_path / "missing-profile.json"),
            *mode_options,
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["remote_operations"] == expected_remote
    assert not project.exists()


def test_run_dry_run_rejects_invalid_run_identifier_before_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("biopipe.cli.run.query_run_status", _forbidden)

    result = runner.invoke(
        app,
        [
            "run",
            str(tmp_path / "project"),
            "--execution-profile",
            str(tmp_path / "profile.json"),
            "--status",
            "not-a-run-id",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "VALIDATION_FAILED"


def test_schema_export_dry_run_does_not_create_output(tmp_path: Path) -> None:
    output = tmp_path / "schemas"

    result = runner.invoke(
        app,
        ["schema", "export", "--output", str(output), "--dry-run", "--json"],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == "would_export"
    assert not output.exists()
