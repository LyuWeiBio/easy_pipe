"""M4 synthetic-only Nextflow runner and bounded subprocess tests."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest

import biopipe.workflow_test.runner as workflow_runner_module
from biopipe.compiler import NextflowCompiler
from biopipe.manifests import finalize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetSample,
    LaneFiles,
    ManifestSource,
)
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import load_default_registry
from biopipe.workflow_test import (
    CommandResult,
    FixtureValidationError,
    SubprocessCommandRunner,
    WorkflowTestCode,
    WorkflowTestRunner,
    WorkflowTestStatus,
    load_synthetic_fixture,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "m4"


@dataclass(slots=True)
class _FakeCommandRunner:
    callback: Callable[[tuple[str, ...]], None] | None = None
    result_factory: Callable[[tuple[str, ...]], CommandResult] | None = None
    calls: list[tuple[tuple[str, ...], Path, dict[str, str], float, int]] = field(
        default_factory=list
    )

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandResult:
        arguments = tuple(argv)
        self.calls.append((arguments, cwd, dict(env), timeout_seconds, output_limit_bytes))
        if self.callback is not None:
            self.callback(arguments)
        if self.result_factory is not None:
            return self.result_factory(arguments)
        tool_versions = {
            "fastp": "fastp 1.3.6\n",
            "fastqc": "FastQC v0.12.1\n",
            "multiqc": "multiqc, version 1.35\n",
        }
        executable = Path(arguments[0]).name
        return CommandResult(
            argv=arguments,
            return_code=0,
            stdout=tool_versions.get(executable, "synthetic command output"),
            stderr="",
        )


def _finder(
    *,
    nextflow: bool = True,
    nf_test: bool = False,
    native_tools: bool = True,
):
    executables = {
        "nextflow": "/reviewed/bin/nextflow" if nextflow else None,
        "nf-test": "/reviewed/bin/nf-test" if nf_test else None,
        "fastqc": "/reviewed/bin/fastqc" if native_tools else None,
        "fastp": "/reviewed/bin/fastp" if native_tools else None,
        "multiqc": "/reviewed/bin/multiqc" if native_tools else None,
    }
    return lambda name: executables.get(name)


def _generated_project(
    tmp_path: Path,
    *,
    layout: str,
    trimming: bool,
) -> Path:
    private_root = "/srv/private-real-data"
    read2 = f"{private_root}/private_R2.fastq" if layout == "paired_end" else None
    manifest = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="private-source",
                root=private_root,
                scanned_at=datetime(2026, 7, 18, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="generic_fastq",
                layout=layout,  # type: ignore[arg-type]
                confidence=1.0,
            ),
            samples=[
                DatasetSample(
                    sample_id="private-sample",
                    lanes=[
                        LaneFiles(
                            lane="L001",
                            chunk="001",
                            read1=f"{private_root}/private_R1.fastq",
                            read2=read2,
                        )
                    ],
                )
            ],
        )
    )
    planned = plan_fastq_qc(
        manifest,
        PlanningOptions(
            project_name=f"synthetic-{layout}",
            trimming_enabled=trimming,
            work_dir="/opt/biopipe-m4/work",
            output_dir="/opt/biopipe-m4/results",
            container_cache="/opt/biopipe-m4/container-cache",
            max_cpus=8,
            max_memory_gb=16,
        ),
    )
    project = tmp_path / "generated"
    NextflowCompiler().compile_planned(
        project,
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )
    return project


def _runner(
    command_runner: _FakeCommandRunner,
    *,
    nextflow: bool = True,
    nf_test: bool = False,
    native_tools: bool = True,
) -> WorkflowTestRunner:
    return WorkflowTestRunner(
        command_runner=command_runner,
        executable_finder=_finder(
            nextflow=nextflow,
            nf_test=nf_test,
            native_tools=native_tools,
        ),
        parent_environment={
            "PATH": "/reviewed/bin:/usr/bin",
            "JAVA_HOME": "/reviewed/java",
            "AWS_SECRET_ACCESS_KEY": "must-not-cross-boundary",
            "HTTP_PROXY": "must-not-cross-boundary",
        },
    )


def _output_callback(*, paired: bool, trimming: bool, e2e: bool = False):
    def create(arguments: tuple[str, ...]) -> None:
        if "run" not in arguments or "-preview" in arguments:
            return
        output_root = Path(arguments[arguments.index("--output_dir") + 1])
        sample = "synthetic_pe_001" if paired else "synthetic_se_001"
        _fastqc_outputs(
            output_root / "fastqc_raw" / sample / "L001" / "001",
            sample=sample,
            label="raw",
            paired=paired,
            e2e=e2e,
        )
        process_names = ["FASTQ_QC:FASTQC_RAW"]
        if trimming:
            fastp = output_root / "fastp" / sample / "L001" / "001"
            fastp.mkdir(parents=True)
            prefix = f"{sample}_L001_001"
            suffixes = (
                (".R1.trimmed.fastq.gz", ".R2.trimmed.fastq.gz")
                if paired
                else (".trimmed.fastq.gz",)
            )
            for suffix in suffixes:
                path = fastp / f"{prefix}{suffix}"
                if e2e:
                    with gzip.open(path, "wb") as stream:
                        stream.write(b"@SYNTHETIC_OUTPUT\nACGTACGT\n+\nIIIIIIII\n")
                else:
                    path.write_text("stub\n", encoding="utf-8")
            (fastp / f"{prefix}.fastp.json").write_text(
                "{}\n" if e2e else "stub\n",
                encoding="utf-8",
            )
            _write_html(fastp / f"{prefix}.fastp.html", e2e=e2e)
            _fastqc_outputs(
                output_root / "fastqc_trimmed" / sample / "L001" / "001",
                sample=sample,
                label="trimmed",
                paired=paired,
                e2e=e2e,
            )
            process_names.extend(("FASTQ_QC:FASTP", "FASTQ_QC:FASTQC_POST_TRIM"))
        multiqc = output_root / "multiqc"
        multiqc.mkdir(parents=True)
        _write_html(multiqc / "multiqc_report.html", e2e=e2e)
        data = multiqc / "multiqc_data"
        data.mkdir()
        (data / "multiqc_data.json").write_text("{}\n", encoding="utf-8")
        process_names.append("FASTQ_QC:MULTIQC")

        pipeline_info = output_root / "pipeline_info"
        pipeline_info.mkdir(parents=True)
        trace = "name\tstatus\n" + "".join(f"{name}\tCOMPLETED\n" for name in process_names)
        (pipeline_info / "execution_trace.txt").write_text(trace, encoding="utf-8")
        for filename in ("execution_report.html", "timeline.html", "pipeline_dag.html"):
            _write_html(pipeline_info / filename, e2e=e2e)

    return create


def _fastqc_outputs(
    directory: Path,
    *,
    sample: str,
    label: str,
    paired: bool,
    e2e: bool,
) -> None:
    directory.mkdir(parents=True)
    prefix = f"{sample}_L001_001_{label}"
    for read in ("read1", "read2") if paired else ("read1",):
        archive = directory / f"{prefix}.{read}_fastqc.zip"
        if e2e:
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("summary.txt", "PASS\tSynthetic\n")
        else:
            archive.write_text("stub\n", encoding="utf-8")
        _write_html(directory / f"{prefix}.{read}_fastqc.html", e2e=e2e)


def _write_html(path: Path, *, e2e: bool) -> None:
    path.write_text(
        "<!doctype html><html><body>Synthetic</body></html>\n" if e2e else "stub\n",
        encoding="utf-8",
    )


def test_committed_fixtures_are_tiny_reserved_and_pair_consistent() -> None:
    single = load_synthetic_fixture(FIXTURES / "single_end")
    paired = load_synthetic_fixture(FIXTURES / "paired_end")

    assert single.layout == "single_end"
    assert paired.layout == "paired_end"
    assert all(row.sample_id.startswith("synthetic_") for row in (*single.rows, *paired.rows))
    assert sum(path.stat().st_size for path in (row.read1 for row in single.rows)) < 1_024
    assert (
        sum(
            path.stat().st_size
            for row in paired.rows
            for path in (row.read1, row.read2)
            if path is not None
        )
        < 2_048
    )


def test_fixture_loader_rejects_non_reserved_read_identifiers(tmp_path: Path) -> None:
    fixture = tmp_path / "bad-fixture"
    reads = fixture / "reads"
    reads.mkdir(parents=True)
    (fixture / "fixture.json").write_text(
        json.dumps(
            {
                "fixture_version": "1.0",
                "synthetic": True,
                "layout": "single_end",
                "rows": [
                    {
                        "sample_id": "synthetic_se_999",
                        "lane": "L001",
                        "read1": "reads/read1.fastq",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (reads / "read1.fastq").write_text(
        "@PATIENT_IDENTIFIER\nACGT\n+\nIIII\n",
        encoding="utf-8",
    )

    with pytest.raises(FixtureValidationError):
        load_synthetic_fixture(fixture)


def test_validate_uses_only_synthetic_overrides_and_stable_degraded_report(
    tmp_path: Path,
) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    first_commands = _FakeCommandRunner()
    second_commands = _FakeCommandRunner()

    first = _runner(first_commands).validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "validate-one",
    )
    second = _runner(second_commands).validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "validate-two",
    )

    assert first.status is WorkflowTestStatus.DEGRADED
    assert first.code is WorkflowTestCode.NF_TEST_NOT_FOUND
    assert first.to_json() == second.to_json()
    assert len(first_commands.calls) == 3
    config_argv = first_commands.calls[0][0]
    lint_argv = first_commands.calls[1][0]
    syntax_argv = first_commands.calls[2][0]
    assert "config" in config_argv
    assert "-o" in config_argv
    assert "json" in config_argv
    assert "lint" in lint_argv
    assert "concise" in lint_argv
    assert "-preview" in syntax_argv
    assert "--samplesheet" in syntax_argv
    assert "--source_root" in syntax_argv
    assert "/srv/private-real-data" not in "\n".join(syntax_argv)
    snapshot_project = tmp_path / "validate-one/project"
    assert str(snapshot_project) in config_argv
    assert str(project) not in config_argv
    assert syntax_argv[syntax_argv.index("--source_root") + 1] == str(
        tmp_path / "validate-one/syntax/inputs"
    )
    snapshot_sheet = tmp_path / "validate-one/syntax/assets/samplesheet.csv"
    assert str(FIXTURES) not in snapshot_sheet.read_text(encoding="utf-8")
    runtime_config = (tmp_path / "validate-one/syntax/test.config").read_text(encoding="utf-8")
    assert "executor.cpus = 8" in runtime_config
    assert "executor.memory = '16 GB'" in runtime_config
    environment = first_commands.calls[0][2]
    assert set(environment) == {
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "NXF_ANSI_LOG",
        "NXF_HOME",
        "NXF_OFFLINE",
        "PATH",
        "TMPDIR",
    }
    assert "must-not-cross-boundary" not in first.to_json()


def test_missing_nextflow_is_blocked_not_success(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    commands = _FakeCommandRunner()

    report = _runner(commands, nextflow=False).validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "blocked",
    )

    assert report.status is WorkflowTestStatus.BLOCKED
    assert report.code is WorkflowTestCode.NEXTFLOW_NOT_FOUND
    assert not commands.calls


def test_command_timeout_and_output_limit_have_stable_failure_codes(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)

    for code, result in (
        (
            WorkflowTestCode.COMMAND_TIMEOUT,
            CommandResult(
                argv=("nextflow",),
                return_code=-15,
                stdout="",
                stderr="",
                timed_out=True,
            ),
        ),
        (
            WorkflowTestCode.COMMAND_OUTPUT_LIMIT,
            CommandResult(
                argv=("nextflow",),
                return_code=-15,
                stdout="x" * 10,
                stderr="",
                output_limit_exceeded=True,
            ),
        ),
    ):
        commands = _FakeCommandRunner(result_factory=lambda _arguments, value=result: value)
        report = _runner(commands).validate(
            project,
            fixture_root=FIXTURES / "single_end",
            runtime_directory=tmp_path / code.value.lower(),
        )
        assert report.status is WorkflowTestStatus.FAILED
        assert report.code is code


def test_stub_run_asserts_single_end_output_structure(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    commands = _FakeCommandRunner(callback=_output_callback(paired=False, trimming=False))

    report = _runner(commands).stub_run(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "stub",
    )

    assert report.status is WorkflowTestStatus.DEGRADED
    assert report.code is WorkflowTestCode.NF_TEST_NOT_FOUND
    assert any(check.name == "workflow_outputs" for check in report.checks)
    run_argv = next(call[0] for call in commands.calls if "-stub-run" in call[0])
    assert "-stub-run" in run_argv
    assert "-c" in run_argv
    assert "fastqc_raw/synthetic_se_001/L001/001" in "\n".join(report.outputs)


def test_paired_trimming_e2e_parses_key_outputs_and_trace(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="paired_end", trimming=True)
    commands = _FakeCommandRunner(callback=_output_callback(paired=True, trimming=True, e2e=True))

    report = _runner(commands).e2e_run(
        project,
        fixture_root=FIXTURES / "paired_end",
        runtime_directory=tmp_path / "e2e",
    )

    assert report.status is WorkflowTestStatus.DEGRADED
    assert report.code is WorkflowTestCode.NF_TEST_NOT_FOUND
    assert any(name.endswith(".R1.trimmed.fastq.gz") for name in report.outputs)
    assert any(name.endswith(".R2.trimmed.fastq.gz") for name in report.outputs)
    e2e_argv = next(
        call[0] for call in commands.calls if "run" in call[0] and "-preview" not in call[0]
    )
    assert "-stub-run" not in e2e_argv
    assert "-c" in e2e_argv


def test_e2e_requires_locked_native_component_versions(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="paired_end", trimming=True)

    missing = _runner(_FakeCommandRunner(), native_tools=False).e2e_run(
        project,
        fixture_root=FIXTURES / "paired_end",
        runtime_directory=tmp_path / "missing-native-tools",
    )
    assert missing.status is WorkflowTestStatus.BLOCKED
    assert missing.code is WorkflowTestCode.TOOL_NOT_FOUND

    def mismatched_version(arguments: tuple[str, ...]) -> CommandResult:
        output = "fastp 1.3.5\n" if Path(arguments[0]).name == "fastp" else "ok\n"
        return CommandResult(
            argv=arguments,
            return_code=0,
            stdout=output,
            stderr="",
        )

    mismatch = _runner(
        _FakeCommandRunner(result_factory=mismatched_version),
    ).e2e_run(
        project,
        fixture_root=FIXTURES / "paired_end",
        runtime_directory=tmp_path / "mismatched-native-version",
    )
    assert mismatch.status is WorkflowTestStatus.FAILED
    assert mismatch.code is WorkflowTestCode.TOOL_VERSION_MISMATCH


def test_missing_key_output_fails_even_when_nextflow_returns_zero(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    commands = _FakeCommandRunner()

    report = _runner(commands).stub_run(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "missing-output",
    )

    assert report.status is WorkflowTestStatus.FAILED
    assert report.code is WorkflowTestCode.OUTPUT_ASSERTION_FAILED


def test_tampered_generated_code_is_rejected_before_any_command(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    with (project / "main.nf").open("a", encoding="utf-8") as stream:
        stream.write("\n// tampered\n")
    commands = _FakeCommandRunner()

    report = _runner(commands).validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "never-created",
    )

    assert report.status is WorkflowTestStatus.FAILED
    assert report.code is WorkflowTestCode.PROJECT_INVALID
    assert not commands.calls
    assert not (tmp_path / "never-created").exists()


def test_runtime_uses_verified_project_and_fixture_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    fixture_root = tmp_path / "fixture"
    shutil.copytree(FIXTURES / "single_end", fixture_root)
    validated_fixture = load_synthetic_fixture(fixture_root)
    original_payload = validated_fixture.rows[0].read1_payload
    validated_fixture.rows[0].read1.write_text(
        "@UNVALIDATED_REAL_IDENTIFIER\nACGT\n+\nIIII\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        workflow_runner_module,
        "load_synthetic_fixture",
        lambda _root: validated_fixture,
    )

    commands = _FakeCommandRunner()
    runtime = tmp_path / "snapshot-runtime"
    report = _runner(commands).validate(
        project,
        fixture_root=fixture_root,
        runtime_directory=runtime,
    )

    assert report.status is WorkflowTestStatus.DEGRADED
    snapshot_read = runtime / "syntax/inputs/reads/synthetic_se_R1.fastq"
    assert snapshot_read.read_bytes() == original_payload
    assert b"UNVALIDATED_REAL_IDENTIFIER" not in snapshot_read.read_bytes()
    for arguments, _cwd, _environment, _timeout, _limit in commands.calls:
        assert str(project) not in arguments
        assert str(runtime / "project") in arguments


def test_layout_mismatch_and_runtime_overlap_are_rejected(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)

    mismatch = _runner(_FakeCommandRunner()).validate(
        project,
        fixture_root=FIXTURES / "paired_end",
        runtime_directory=tmp_path / "layout-mismatch",
    )
    assert mismatch.code is WorkflowTestCode.FIXTURE_LAYOUT_MISMATCH

    overlap = FIXTURES / "single_end" / "unsafe-runtime"
    report = _runner(_FakeCommandRunner()).validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=overlap,
    )
    assert report.status is WorkflowTestStatus.BLOCKED
    assert report.code is WorkflowTestCode.RUNTIME_DIRECTORY_CONFLICT
    assert not overlap.exists()


def test_nf_test_suite_runs_from_project_with_isolated_work_and_log(tmp_path: Path) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    commands = _FakeCommandRunner()
    runtime = tmp_path / "nf-test-runtime"
    report = _runner(commands, nf_test=True).validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=runtime,
    )

    assert report.status is WorkflowTestStatus.PASSED
    nf_test_call = next(call for call in commands.calls if Path(call[0][0]).name == "nf-test")
    assert "tests/pipeline.nf.test" in nf_test_call[0]
    assert nf_test_call[1] == runtime / "project"
    assert nf_test_call[2]["BIOPIPE_NF_TEST_WORK_DIR"] == str(runtime / "nf-test/work")
    assert str(runtime / "nf-test/nf-test.log") in nf_test_call[0]
    assert not (project / ".nf-test").exists()
    assert not (project / ".nf-test.log").exists()


def test_nf_test_ci_diagnostic_is_opt_in_bounded_and_path_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _generated_project(tmp_path, layout="single_end", trimming=False)
    private_path = "/srv/private-real-data/sample.fastq"
    commands = _FakeCommandRunner(
        result_factory=lambda arguments: CommandResult(
            argv=arguments,
            return_code=1 if Path(arguments[0]).name == "nf-test" else 0,
            stdout=f"FAILED at {private_path}\n" + "x" * 600,
            stderr="synthetic assertion failed\n",
        )
    )
    runner = WorkflowTestRunner(
        command_runner=commands,
        executable_finder=_finder(nf_test=True),
        parent_environment={
            "BIOPIPE_SYNTHETIC_CI_DIAGNOSTICS": "1",
            "PATH": os.defpath,
        },
    )

    report = runner.validate(
        project,
        fixture_root=FIXTURES / "single_end",
        runtime_directory=tmp_path / "diagnostic-runtime",
    )

    captured = capsys.readouterr()
    assert report.code is WorkflowTestCode.NF_TEST_FAILED
    assert private_path not in captured.err
    assert "FAILED at <PATH>" in captured.err
    assert "BIOPIPE_SYNTHETIC_DIAGNOSTIC_BEGIN" in captured.err
    assert max(map(len, captured.err.splitlines())) <= 300


def test_real_subprocess_runner_uses_shell_false_timeout_and_output_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = subprocess.Popen
    observed: list[dict[str, object]] = []

    def recording_popen(*args: object, **kwargs: object):
        observed.append(dict(kwargs))
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", recording_popen)
    runner = SubprocessCommandRunner()
    environment = {"PATH": os.defpath, "LANG": "C"}

    success = runner.run(
        (sys.executable, "-c", "print('synthetic')"),
        cwd=tmp_path,
        env=environment,
        timeout_seconds=2,
        output_limit_bytes=1_024,
    )
    assert success.return_code == 0
    assert success.stdout == "synthetic\n"
    assert observed[0]["shell"] is False
    assert observed[0]["env"] == environment
    assert observed[0]["start_new_session"] is (os.name == "posix")

    timed_out = runner.run(
        (sys.executable, "-c", "import time; time.sleep(5)"),
        cwd=tmp_path,
        env=environment,
        timeout_seconds=0.05,
        output_limit_bytes=1_024,
    )
    assert timed_out.timed_out is True

    bounded = runner.run(
        (sys.executable, "-c", "print('x' * 10000)"),
        cwd=tmp_path,
        env=environment,
        timeout_seconds=2,
        output_limit_bytes=128,
    )
    assert bounded.output_limit_exceeded is True
    assert len(bounded.stdout.encode("utf-8")) <= 128
