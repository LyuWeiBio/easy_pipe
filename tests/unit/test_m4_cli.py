"""M4 CLI report, exit-status, and synthetic-only orchestration tests."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from typer.testing import CliRunner

import biopipe.cli.test as test_cli
import biopipe.cli.validate as validate_cli
from biopipe.cli.app import app
from biopipe.cli.reports import write_project_report_atomic
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.validation import (
    FindingCode,
    ValidationFinding,
    ValidationReport,
)
from biopipe.workflow_test import (
    WorkflowTestCode,
    WorkflowTestReport,
    WorkflowTestStatus,
)

runner = CliRunner()


def _static_report(project: Path, *, valid: bool = True) -> ValidationReport:
    findings = []
    if not valid:
        findings.append(
            ValidationFinding(
                code=FindingCode.GENERATED_CONTENT_MISMATCH,
                artifact="main.nf",
                message="A generated template artifact differs from the reviewed compiler output.",
                remediation=["Regenerate the complete project."],
            )
        )
    return ValidationReport(
        project_directory=str(project.absolute()),
        status="valid" if valid else "invalid",
        checked_artifacts=["main.nf"],
        artifact_hashes={"main.nf": "a" * 64},
        findings=findings,
    )


def _workflow_report(
    mode: str,
    *,
    status: WorkflowTestStatus = WorkflowTestStatus.PASSED,
    code: WorkflowTestCode = WorkflowTestCode.OK,
) -> WorkflowTestReport:
    return WorkflowTestReport(
        mode=mode,  # type: ignore[arg-type]
        status=status,
        code=code,
        layout="single_end",
        trimming_enabled=False,
        remediation=("Install the missing reviewed runtime.",) if status != "passed" else (),
    )


@dataclass
class _FakeRunner:
    validate_report: WorkflowTestReport = field(
        default_factory=lambda: _workflow_report("validate")
    )
    stub_report: WorkflowTestReport = field(default_factory=lambda: _workflow_report("stub"))
    e2e_report: WorkflowTestReport = field(default_factory=lambda: _workflow_report("e2e"))
    calls: list[tuple[str, Path, Path]] = field(default_factory=list)

    def validate(
        self,
        project_directory: Path,
        *,
        fixture_root: Path,
        runtime_directory: Path,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> WorkflowTestReport:
        del project_directory, timeout_seconds, output_limit_bytes
        assert not runtime_directory.exists()
        self.calls.append(("validate", fixture_root, runtime_directory))
        return self.validate_report

    def stub_run(
        self,
        project_directory: Path,
        *,
        fixture_root: Path,
        runtime_directory: Path,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> WorkflowTestReport:
        del project_directory, timeout_seconds, output_limit_bytes
        assert not runtime_directory.exists()
        self.calls.append(("stub", fixture_root, runtime_directory))
        return self.stub_report

    def e2e_run(
        self,
        project_directory: Path,
        *,
        fixture_root: Path,
        runtime_directory: Path,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> WorkflowTestReport:
        del project_directory, timeout_seconds, output_limit_bytes
        assert not runtime_directory.exists()
        self.calls.append(("e2e", fixture_root, runtime_directory))
        return self.e2e_report


def test_validate_uses_default_fixture_and_atomically_replaces_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    project.mkdir()
    fake = _FakeRunner()
    monkeypatch.setattr(
        validate_cli,
        "validate_generated_project",
        lambda _project: _static_report(project),
    )
    monkeypatch.setattr(validate_cli, "_project_layout", lambda _project: "single_end")
    monkeypatch.setattr(validate_cli, "WorkflowTestRunner", lambda: fake)

    first = runner.invoke(app, ["validate", str(project), "--json"])
    second = runner.invoke(app, ["validate", str(project), "--json"])

    assert first.exit_code == second.exit_code == 0
    assert json.loads(first.stdout) == json.loads(second.stdout)
    payload = json.loads((project / "reports" / "validation.json").read_text())
    assert payload["status"] == "passed"
    assert payload["runtime_validation"]["mode"] == "validate"
    assert payload["report_path"] == "reports/validation.json"
    default_fixture = project / "tests" / "fixtures" / "single_end"
    assert [call[1] for call in fake.calls] == [default_fixture, default_fixture]
    assert not list((project / "reports").glob(".*.tmp"))


def test_validate_static_failure_is_reported_without_starting_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    project.mkdir()
    monkeypatch.setattr(
        validate_cli,
        "validate_generated_project",
        lambda _project: _static_report(project, valid=False),
    )
    monkeypatch.setattr(
        validate_cli,
        "WorkflowTestRunner",
        lambda: pytest.fail("runtime must not start after static validation failure"),
    )

    result = runner.invoke(app, ["validate", str(project), "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["code"] == FindingCode.GENERATED_CONTENT_MISMATCH.value
    assert payload["runtime_validation"] is None
    assert json.loads((project / "reports" / "validation.json").read_text()) == payload


def test_validate_explicit_fixture_and_blocked_status_are_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    fixture = tmp_path / "fixture"
    project.mkdir()
    fixture.mkdir()
    fake = _FakeRunner(
        validate_report=_workflow_report(
            "validate",
            status=WorkflowTestStatus.BLOCKED,
            code=WorkflowTestCode.NEXTFLOW_NOT_FOUND,
        )
    )
    monkeypatch.setattr(
        validate_cli,
        "validate_generated_project",
        lambda _project: _static_report(project),
    )
    monkeypatch.setattr(validate_cli, "_project_layout", lambda _project: "single_end")
    monkeypatch.setattr(validate_cli, "WorkflowTestRunner", lambda: fake)

    result = runner.invoke(
        app,
        ["validate", str(project), "--fixture-root", str(fixture), "--json"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["code"] == WorkflowTestCode.NEXTFLOW_NOT_FOUND.value
    assert fake.calls[0][1] == fixture


def test_test_profile_runs_stub_then_e2e_and_is_repeatable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    project.mkdir()
    fake = _FakeRunner()
    monkeypatch.setattr(
        test_cli,
        "validate_generated_project",
        lambda _project: _static_report(project),
    )
    monkeypatch.setattr(test_cli, "_project_layout", lambda _project: "single_end")
    monkeypatch.setattr(test_cli, "WorkflowTestRunner", lambda: fake)

    first = runner.invoke(app, ["test", str(project), "--profile", "test", "--json"])
    second = runner.invoke(app, ["test", str(project), "--profile", "test", "--json"])

    assert first.exit_code == second.exit_code == 0
    assert json.loads(first.stdout) == json.loads(second.stdout)
    payload = json.loads((project / "reports" / "test.json").read_text())
    assert payload["status"] == "passed"
    assert sorted(payload["runs"]) == ["e2e", "stub"]
    assert [call[0] for call in fake.calls] == ["stub", "e2e", "stub", "e2e"]
    assert all(call[1] == project / "tests" / "fixtures" / "single_end" for call in fake.calls)


def test_test_stops_after_stub_failure_and_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    project.mkdir()
    fake = _FakeRunner(
        stub_report=_workflow_report(
            "stub",
            status=WorkflowTestStatus.FAILED,
            code=WorkflowTestCode.STUB_RUN_FAILED,
        )
    )
    monkeypatch.setattr(
        test_cli,
        "validate_generated_project",
        lambda _project: _static_report(project),
    )
    monkeypatch.setattr(test_cli, "_project_layout", lambda _project: "single_end")
    monkeypatch.setattr(test_cli, "WorkflowTestRunner", lambda: fake)

    result = runner.invoke(app, ["test", str(project), "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["code"] == WorkflowTestCode.STUB_RUN_FAILED.value
    assert sorted(payload["runs"]) == ["stub"]
    assert [call[0] for call in fake.calls] == ["stub"]


def test_test_degraded_stub_still_runs_e2e_and_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    project.mkdir()
    fake = _FakeRunner(
        stub_report=_workflow_report(
            "stub",
            status=WorkflowTestStatus.DEGRADED,
            code=WorkflowTestCode.NF_TEST_NOT_FOUND,
        )
    )
    monkeypatch.setattr(
        test_cli,
        "validate_generated_project",
        lambda _project: _static_report(project),
    )
    monkeypatch.setattr(test_cli, "_project_layout", lambda _project: "single_end")
    monkeypatch.setattr(test_cli, "WorkflowTestRunner", lambda: fake)

    result = runner.invoke(app, ["test", str(project), "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "degraded"
    assert payload["code"] == WorkflowTestCode.NF_TEST_NOT_FOUND.value
    assert [call[0] for call in fake.calls] == ["stub", "e2e"]


def test_test_rejects_non_test_profile_without_creating_report(tmp_path: Path) -> None:
    project = tmp_path / "generated"
    project.mkdir()

    result = runner.invoke(app, ["test", str(project), "--profile", "production", "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == ErrorCode.VALIDATION_FAILED.value
    assert payload["error"]["context"] == {"profile": "production"}
    assert not (project / "reports").exists()


def test_report_writer_refuses_unallowlisted_name_and_symlink_directory(
    tmp_path: Path,
) -> None:
    project = tmp_path / "generated"
    project.mkdir()

    with pytest.raises(ValueError, match="allowlisted"):
        write_project_report_atomic(project, "other.json", {"status": "passed"})

    external = tmp_path / "external"
    external.mkdir()
    (project / "reports").symlink_to(external, target_is_directory=True)
    with pytest.raises(BioPipeError) as raised:
        write_project_report_atomic(project, "test.json", {"status": "passed"})
    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not (external / "test.json").exists()


def test_report_writer_rejects_reports_directory_swap_without_escaping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    reports = project / "reports"
    external = tmp_path / "external"
    detached = tmp_path / "detached-reports"
    reports.mkdir(parents=True)
    external.mkdir()
    real_replace = os.replace

    def racing_replace(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        reports.rename(detached)
        reports.symlink_to(external, target_is_directory=True)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr("biopipe.cli.reports.os.replace", racing_replace)

    with pytest.raises(BioPipeError) as raised:
        write_project_report_atomic(project, "test.json", {"status": "passed"})

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not (external / "test.json").exists()
    assert not list(detached.glob(".*.tmp"))


def test_report_writer_rejects_project_root_swap_without_escaping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    reports = project / "reports"
    external = tmp_path / "external"
    detached = tmp_path / "detached-project"
    reports.mkdir(parents=True)
    external.mkdir()
    real_replace = os.replace

    def racing_replace(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        project.rename(detached)
        project.mkdir()
        (project / "reports").symlink_to(external, target_is_directory=True)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr("biopipe.cli.reports.os.replace", racing_replace)

    with pytest.raises(BioPipeError) as raised:
        write_project_report_atomic(project, "validation.json", {"status": "passed"})

    assert raised.value.code == ErrorCode.ARTIFACT_WRITE_FAILED
    assert not (external / "validation.json").exists()
    assert not list((detached / "reports").glob(".*.tmp"))
