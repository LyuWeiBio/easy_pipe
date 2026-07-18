"""Isolated Nextflow config, syntax, stub, and synthetic E2E orchestration."""

from __future__ import annotations

import math
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError
from biopipe.io import read_model
from biopipe.manifests.integrity import require_valid_manifest
from biopipe.models import DatasetManifest, ExecutionPlan, PipelineSpec, SoftwareLock
from biopipe.planner import PlannedPipeline, reconstruct_planned_pipeline
from biopipe.registry import load_default_registry
from biopipe.workflow_test.fixtures import (
    FixtureValidationError,
    SyntheticFastqFixture,
    load_synthetic_fixture,
    render_synthetic_samplesheet,
)
from biopipe.workflow_test.models import (
    WorkflowCheck,
    WorkflowTestCode,
    WorkflowTestReport,
    WorkflowTestStatus,
)
from biopipe.workflow_test.outputs import OutputAssertionError, assert_workflow_outputs
from biopipe.workflow_test.subprocess_runner import (
    CommandResult,
    CommandRunner,
    SubprocessCommandRunner,
)

_MAX_PROJECT_ARTIFACT_BYTES = 16 * 1024 * 1024
_DEFAULT_TIMEOUT_SECONDS = 300.0
_DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ABSOLUTE_PATH = re.compile(r"/(?:[A-Za-z0-9._@+-]+/)*[A-Za-z0-9._@+-]+")
_NO_CONTAINER_CONFIG = """\
docker.enabled = false
apptainer.enabled = false
singularity.enabled = false
podman.enabled = false
charliecloud.enabled = false
conda.enabled = false
wave.enabled = false
"""
_SYNTAX_CONFIG = (
    _NO_CONTAINER_CONFIG
    + """\
timeline.enabled = false
report.enabled = false
trace.enabled = false
dag.enabled = false
"""
)


class _ProjectValidationError(ValueError):
    pass


class _RuntimeConflictError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProjectContext:
    root: Path
    manifest: DatasetManifest
    planned: PlannedPipeline


class WorkflowTestRunner:
    """Run only controlled commands against committed synthetic FASTQ data."""

    def __init__(
        self,
        *,
        command_runner: CommandRunner | None = None,
        executable_finder: Callable[[str], str | None] | None = None,
        parent_environment: Mapping[str, str] | None = None,
    ) -> None:
        self._command_runner = command_runner or SubprocessCommandRunner()
        self._parent_environment = dict(
            os.environ if parent_environment is None else parent_environment
        )
        search_path = self._parent_environment.get("PATH", os.defpath)
        self._executable_finder = executable_finder or (
            lambda executable: shutil.which(executable, path=search_path)
        )

    def validate(
        self,
        project_directory: str | Path,
        *,
        fixture_root: str | Path,
        runtime_directory: str | Path,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        output_limit_bytes: int = _DEFAULT_OUTPUT_LIMIT_BYTES,
    ) -> WorkflowTestReport:
        """Run project structure, config, lint, preview, and optional nf-test checks."""

        return self._run(
            "validate",
            project_directory,
            fixture_root=fixture_root,
            runtime_directory=runtime_directory,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )

    def stub_run(
        self,
        project_directory: str | Path,
        *,
        fixture_root: str | Path,
        runtime_directory: str | Path,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        output_limit_bytes: int = _DEFAULT_OUTPUT_LIMIT_BYTES,
    ) -> WorkflowTestReport:
        """Execute the fixed graph with ``-stub-run`` and assert key outputs."""

        return self._run(
            "stub",
            project_directory,
            fixture_root=fixture_root,
            runtime_directory=runtime_directory,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )

    def e2e_run(
        self,
        project_directory: str | Path,
        *,
        fixture_root: str | Path,
        runtime_directory: str | Path,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        output_limit_bytes: int = _DEFAULT_OUTPUT_LIMIT_BYTES,
    ) -> WorkflowTestReport:
        """Execute pinned components on synthetic FASTQs and parse their outputs."""

        return self._run(
            "e2e",
            project_directory,
            fixture_root=fixture_root,
            runtime_directory=runtime_directory,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )

    def _run(
        self,
        mode: Literal["validate", "stub", "e2e"],
        project_directory: str | Path,
        *,
        fixture_root: str | Path,
        runtime_directory: str | Path,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> WorkflowTestReport:
        checks: list[WorkflowCheck] = []
        try:
            _validate_limits(timeout_seconds, output_limit_bytes)
            project = _load_project(project_directory)
        except (BioPipeError, ValueError, OSError) as exc:
            check = _failed_check(
                "project_structure",
                WorkflowTestCode.PROJECT_INVALID,
                "The generated project is missing, unsafe, or internally inconsistent.",
                ("Regenerate the project from verified M3 artifacts.",),
            )
            return _terminal_report(mode, check, checks, cause=exc)
        checks.append(_passed_check("project_structure", "Generated project contracts are valid."))

        try:
            fixture = load_synthetic_fixture(fixture_root)
        except FixtureValidationError as exc:
            check = _failed_check(
                "synthetic_fixture",
                WorkflowTestCode.FIXTURE_INVALID,
                "The synthetic FASTQ fixture is missing or invalid.",
                ("Use a bounded fixture with reserved SYNTHETIC_ read identifiers.",),
            )
            return _terminal_report(mode, check, checks, project=project, cause=exc)
        if fixture.layout != project.planned.spec.input.layout:
            check = _failed_check(
                "synthetic_fixture",
                WorkflowTestCode.FIXTURE_LAYOUT_MISMATCH,
                "The synthetic fixture layout does not match the generated pipeline.",
                ("Select the matching single-end or paired-end synthetic fixture.",),
            )
            return _terminal_report(mode, check, checks, project=project)
        checks.append(_passed_check("synthetic_fixture", "Synthetic fixture is bounded and valid."))

        try:
            runtime = _create_runtime_directory(
                runtime_directory,
                project=project.root,
                fixture=fixture.root,
            )
            project_snapshot = runtime / "project"
            NextflowCompiler().compile_planned(
                project_snapshot,
                manifest=project.manifest,
                planned=project.planned,
                registry=load_default_registry(),
            )
            project = _ProjectContext(
                root=project_snapshot,
                manifest=project.manifest,
                planned=project.planned,
            )
            syntax_case = _prepare_case(runtime / "syntax", fixture, syntax_only=True)
            run_case = (
                None
                if mode == "validate"
                else _prepare_case(runtime / "run", fixture, syntax_only=False)
            )
            environment = _restricted_environment(runtime, self._parent_environment)
        except (BioPipeError, OSError, ValueError) as exc:
            check = _blocked_check(
                "runtime_directory",
                WorkflowTestCode.RUNTIME_DIRECTORY_CONFLICT,
                "An isolated create-only workflow test directory could not be prepared.",
                ("Choose a new directory outside the project and synthetic fixture roots.",),
            )
            return _terminal_report(mode, check, checks, project=project, cause=exc)
        checks.append(_passed_check("runtime_directory", "Isolated test paths were created."))

        nextflow = self._find_executable("nextflow")
        if nextflow is None:
            check = _blocked_check(
                "nextflow_available",
                WorkflowTestCode.NEXTFLOW_NOT_FOUND,
                "Nextflow is not available in the restricted command environment.",
                ("Install a reviewed Nextflow version and retry the synthetic test.",),
            )
            return _terminal_report(mode, check, checks, project=project)
        checks.append(_passed_check("nextflow_available", "Nextflow executable is available."))

        config_check = self._command_check(
            name="nextflow_config",
            argv=(
                nextflow,
                "-log",
                str(runtime / "nextflow-config.log"),
                "config",
                "-o",
                "json",
                "-profile",
                "local",
                str(project.root),
            ),
            cwd=runtime,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            failure_code=WorkflowTestCode.CONFIG_CHECK_FAILED,
            failure_message="Nextflow could not resolve the generated configuration.",
        )
        checks.append(config_check)
        if config_check.status != WorkflowTestStatus.PASSED:
            return _terminal_report(mode, config_check, checks[:-1], project=project)

        lint_check = self._command_check(
            name="nextflow_lint",
            argv=(
                nextflow,
                "-log",
                str(runtime / "nextflow-lint.log"),
                "lint",
                "-o",
                "concise",
                str(project.root),
            ),
            cwd=runtime,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            failure_code=WorkflowTestCode.LINT_CHECK_FAILED,
            failure_message="Nextflow lint rejected the generated scripts or configuration.",
        )
        checks.append(lint_check)
        if lint_check.status != WorkflowTestStatus.PASSED:
            return _terminal_report(mode, lint_check, checks[:-1], project=project)

        syntax_check = self._command_check(
            name="nextflow_syntax",
            argv=_nextflow_run_argv(
                nextflow,
                project.root,
                syntax_case,
                runtime / "nextflow-syntax.log",
                source_root=syntax_case / "inputs",
                preview=True,
                stub=False,
                add_config=True,
            ),
            cwd=syntax_case,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            failure_code=WorkflowTestCode.SYNTAX_CHECK_FAILED,
            failure_message="Nextflow preview rejected the generated workflow syntax or graph.",
        )
        checks.append(syntax_check)
        if syntax_check.status != WorkflowTestStatus.PASSED:
            return _terminal_report(mode, syntax_check, checks[:-1], project=project)

        outputs: tuple[str, ...] = ()
        if run_case is not None:
            if mode == "e2e":
                for tool_name, locked in sorted(project.planned.software_lock.components.items()):
                    version_check = self._native_tool_version_check(
                        tool_name,
                        locked.version,
                        cwd=run_case,
                        environment=environment,
                        timeout_seconds=timeout_seconds,
                        output_limit_bytes=output_limit_bytes,
                    )
                    checks.append(version_check)
                    if version_check.status != WorkflowTestStatus.PASSED:
                        return _terminal_report(
                            mode,
                            version_check,
                            checks[:-1],
                            project=project,
                        )
            run_code = (
                WorkflowTestCode.STUB_RUN_FAILED
                if mode == "stub"
                else WorkflowTestCode.E2E_RUN_FAILED
            )
            run_check = self._command_check(
                name=f"nextflow_{mode}",
                argv=_nextflow_run_argv(
                    nextflow,
                    project.root,
                    run_case,
                    runtime / f"nextflow-{mode}.log",
                    source_root=run_case / "inputs",
                    preview=False,
                    stub=mode == "stub",
                    add_config=True,
                ),
                cwd=run_case,
                environment=environment,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
                failure_code=run_code,
                failure_message=(
                    "Nextflow stub execution failed."
                    if mode == "stub"
                    else "Nextflow synthetic end-to-end execution failed."
                ),
            )
            checks.append(run_check)
            if run_check.status != WorkflowTestStatus.PASSED:
                return _terminal_report(mode, run_check, checks[:-1], project=project)
            try:
                output_mode = cast(Literal["stub", "e2e"], mode)
                outputs = assert_workflow_outputs(
                    run_case / "results",
                    fixture,
                    trimming_enabled=project.planned.spec.parameters.trimming.enabled,
                    mode=output_mode,
                )
            except (OSError, OutputAssertionError) as exc:
                output_check = _failed_check(
                    "workflow_outputs",
                    WorkflowTestCode.OUTPUT_ASSERTION_FAILED,
                    "Synthetic execution did not produce the required parseable output structure.",
                    ("Inspect the bounded Nextflow log and generated component templates.",),
                )
                return _terminal_report(
                    mode,
                    output_check,
                    checks,
                    project=project,
                    cause=exc,
                )
            checks.append(
                _passed_check(
                    "workflow_outputs",
                    "Required per-sample, MultiQC, and Nextflow status outputs are present.",
                )
            )

        nf_test_check = self._run_nf_test(
            project,
            runtime,
            environment,
            timeout_seconds,
            output_limit_bytes,
        )
        checks.append(nf_test_check)
        if nf_test_check.status == WorkflowTestStatus.DEGRADED:
            return WorkflowTestReport(
                mode=mode,
                status=WorkflowTestStatus.DEGRADED,
                code=nf_test_check.code,
                layout=project.planned.spec.input.layout,
                trimming_enabled=project.planned.spec.parameters.trimming.enabled,
                checks=tuple(checks),
                outputs=outputs,
                remediation=nf_test_check.remediation,
            )
        if nf_test_check.status != WorkflowTestStatus.PASSED:
            return _terminal_report(
                mode,
                nf_test_check,
                checks[:-1],
                project=project,
                outputs=outputs,
            )
        return WorkflowTestReport(
            mode=mode,
            status=WorkflowTestStatus.PASSED,
            code=WorkflowTestCode.OK,
            layout=project.planned.spec.input.layout,
            trimming_enabled=project.planned.spec.parameters.trimming.enabled,
            checks=tuple(checks),
            outputs=outputs,
        )

    def _native_tool_version_check(
        self,
        tool_name: str,
        expected_version: str,
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> WorkflowCheck:
        executable = self._find_executable(tool_name)
        check_name = f"native_tool_{tool_name}"
        if executable is None:
            return _blocked_check(
                check_name,
                WorkflowTestCode.TOOL_NOT_FOUND,
                "A locked native component is unavailable for synthetic E2E execution.",
                ("Install the exact reviewed M4 test environment and retry.",),
            )
        try:
            result = self._command_runner.run(
                (executable, "--version"),
                cwd=cwd,
                env=environment,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
        except (OSError, ValueError):
            return _failed_check(
                check_name,
                WorkflowTestCode.TOOL_VERSION_CHECK_FAILED,
                "A locked native component did not provide a bounded version response.",
                ("Repair the reviewed M4 test environment and retry.",),
            )
        command_check = _check_from_result(
            check_name,
            result,
            WorkflowTestCode.TOOL_VERSION_CHECK_FAILED,
            "A locked native component version command failed.",
        )
        if command_check.status != WorkflowTestStatus.PASSED:
            return command_check
        observed = f"{result.stdout}\n{result.stderr}"
        version_pattern = re.compile(rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])")
        if version_pattern.search(observed) is None:
            return _failed_check(
                check_name,
                WorkflowTestCode.TOOL_VERSION_MISMATCH,
                "A native component does not match the generated software lock.",
                ("Activate the exact reviewed M4 test environment and retry.",),
                return_code=result.return_code,
            )
        return _passed_check(
            check_name,
            "The native component version matches the generated software lock.",
            result.return_code,
        )

    def _run_nf_test(
        self,
        project: _ProjectContext,
        runtime: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> WorkflowCheck:
        nf_test = self._find_executable("nf-test")
        if nf_test is None:
            return WorkflowCheck(
                name="nf_test",
                status=WorkflowTestStatus.DEGRADED,
                code=WorkflowTestCode.NF_TEST_NOT_FOUND,
                message="nf-test is unavailable; Nextflow checks ran without the nf-test layer.",
                remediation=(
                    "Install a reviewed nf-test release to enable the complete test layer.",
                ),
            )
        test_root = project.root / "tests"
        test_files = tuple(sorted(test_root.rglob("*.nf.test"))) if test_root.is_dir() else ()
        if not test_files:
            return WorkflowCheck(
                name="nf_test",
                status=WorkflowTestStatus.DEGRADED,
                code=WorkflowTestCode.NF_TEST_SUITE_NOT_FOUND,
                message="The generated project has no nf-test suite; Nextflow checks still ran.",
                remediation=(
                    "Generate reviewed nf-test specifications before release validation.",
                ),
            )
        if any(path.is_symlink() or not path.is_file() for path in test_files):
            return _failed_check(
                "nf_test",
                WorkflowTestCode.NF_TEST_FAILED,
                "The generated nf-test suite contains an unsafe test path.",
                ("Regenerate the project test specifications.",),
            )
        nf_test_runtime = runtime / "nf-test"
        nf_test_runtime.mkdir(mode=0o700)
        nf_test_environment = dict(environment)
        nf_test_environment["BIOPIPE_NF_TEST_WORK_DIR"] = str(nf_test_runtime / "work")
        relative_tests = tuple(path.relative_to(project.root).as_posix() for path in test_files)
        return self._command_check(
            name="nf_test",
            argv=(
                nf_test,
                "test",
                *relative_tests,
                "--ci",
                "--log",
                str(nf_test_runtime / "nf-test.log"),
            ),
            cwd=project.root,
            environment=nf_test_environment,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            failure_code=WorkflowTestCode.NF_TEST_FAILED,
            failure_message="nf-test rejected the generated project test suite.",
        )

    def _find_executable(self, name: str) -> str | None:
        candidate = self._executable_finder(name)
        if (
            candidate is None
            or not candidate
            or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
        ):
            return None
        return candidate

    def _command_check(
        self,
        *,
        name: str,
        argv: Sequence[str],
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
        failure_code: WorkflowTestCode,
        failure_message: str,
    ) -> WorkflowCheck:
        try:
            result = self._command_runner.run(
                argv,
                cwd=cwd,
                env=environment,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
        except (OSError, ValueError):
            return _failed_check(
                name,
                failure_code,
                failure_message,
                ("Verify the local test runtime and retry with the same generated project.",),
            )
        if (
            name == "nf_test"
            and result.return_code != 0
            and self._parent_environment.get("BIOPIPE_SYNTHETIC_CI_DIAGNOSTICS") == "1"
        ):
            _emit_synthetic_ci_diagnostic(result)
        return _check_from_result(name, result, failure_code, failure_message)


def _emit_synthetic_ci_diagnostic(result: CommandResult) -> None:
    """Emit a bounded path-free diagnostic only for the fixed synthetic CI run."""

    combined = f"{result.stdout}\n{result.stderr}"
    lines: list[str] = []
    for raw_line in combined.splitlines():
        normalized = _ANSI_ESCAPE.sub("", raw_line)
        normalized = _ABSOLUTE_PATH.sub("<PATH>", normalized)
        normalized = "".join(
            character if character.isprintable() else "?" for character in normalized
        ).strip()
        if normalized:
            lines.append(normalized[:300])
        if len(lines) == 80:
            break
    print("BIOPIPE_SYNTHETIC_DIAGNOSTIC_BEGIN", file=sys.stderr)
    for line in lines:
        print(line, file=sys.stderr)
    print("BIOPIPE_SYNTHETIC_DIAGNOSTIC_END", file=sys.stderr)


def _load_project(project_directory: str | Path) -> _ProjectContext:
    requested = Path(project_directory)
    if requested.is_symlink():
        raise _ProjectValidationError("project root must not be a symlink")
    root = requested.resolve(strict=True)
    if not root.is_dir():
        raise _ProjectValidationError("project root must be a directory")
    required = {
        "main.nf",
        "nextflow.config",
        "conf/base.config",
        "conf/local.config",
        "assets/samplesheet.csv",
        "modules/fastqc/raw.nf",
        "modules/multiqc/main.nf",
        "dataset.manifest.resolved.json",
        "pipeline.spec.yaml",
        "execution.plan.yaml",
        "software.lock.yaml",
    }
    for relative in sorted(required):
        path = root.joinpath(*PurePosixPath(relative).parts)
        if path.is_symlink():
            raise _ProjectValidationError("project artifact must not be a symlink")
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= _MAX_PROJECT_ARTIFACT_BYTES
        ):
            raise _ProjectValidationError("project artifact must be a bounded regular file")
    manifest = read_model(root / "dataset.manifest.resolved.json", DatasetManifest)
    spec = read_model(root / "pipeline.spec.yaml", PipelineSpec)
    execution_plan = read_model(root / "execution.plan.yaml", ExecutionPlan)
    software_lock = read_model(root / "software.lock.yaml", SoftwareLock)
    require_valid_manifest(manifest)
    if manifest.privacy.artifact_scope != "full" or manifest.errors or not manifest.samples:
        raise _ProjectValidationError("project manifest is not executable")
    if manifest.classification.layout != spec.input.layout:
        raise _ProjectValidationError("project manifest and specification layout differ")
    if execution_plan.paths.source_root != manifest.source.root:
        raise _ProjectValidationError("project execution source root differs from the manifest")
    planned = reconstruct_planned_pipeline(spec, execution_plan, software_lock)
    extra_modules = (
        ("modules/fastp/main.nf", "modules/fastqc/post_trim.nf")
        if spec.parameters.trimming.enabled
        else ()
    )
    for relative in extra_modules:
        path = root.joinpath(*PurePosixPath(relative).parts)
        if path.is_symlink() or not path.is_file() or path.stat().st_size < 1:
            raise _ProjectValidationError("selected component module is missing or unsafe")
    _verify_compiler_reproduction(root, manifest, planned)
    return _ProjectContext(root=root, manifest=manifest, planned=planned)


def _verify_compiler_reproduction(
    root: Path,
    manifest: DatasetManifest,
    planned: PlannedPipeline,
) -> None:
    ignored = {"reports/test.json", "reports/validation.json"}
    with tempfile.TemporaryDirectory(prefix="biopipe-m4-verify-") as temporary:
        expected_root = Path(temporary) / "generated"
        NextflowCompiler().compile_planned(
            expected_root,
            manifest=manifest,
            planned=planned,
            registry=load_default_registry(),
        )
        expected = _bounded_tree(expected_root, ignored=ignored)
    actual = _bounded_tree(root, ignored=ignored)
    if actual != expected:
        raise _ProjectValidationError(
            "generated executable files differ from deterministic compiler output"
        )


def _bounded_tree(
    root: Path,
    *,
    ignored: set[str] | None = None,
) -> dict[str, bytes]:
    ignored_names = ignored or set()
    artifacts: dict[str, bytes] = {}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if (current_path / directory).is_symlink():
                raise _ProjectValidationError("generated project contains a symlink")
        for filename in filenames:
            path = current_path / filename
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise _ProjectValidationError("generated project contains a symlink")
            if relative in ignored_names:
                continue
            metadata = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= _MAX_PROJECT_ARTIFACT_BYTES
            ):
                raise _ProjectValidationError("generated project artifact is not bounded")
            artifacts[relative] = path.read_bytes()
            if len(artifacts) > 1_000:
                raise _ProjectValidationError("generated project has too many files")
    return artifacts


def _create_runtime_directory(
    value: str | Path,
    *,
    project: Path,
    fixture: Path,
) -> Path:
    requested = Path(value)
    if not requested.name or any(
        ord(character) < 32 or ord(character) == 127 for character in os.fspath(requested)
    ):
        raise _RuntimeConflictError("runtime path is unsafe")
    if os.path.lexists(requested):
        raise _RuntimeConflictError("runtime path already exists")
    parent = requested.parent.resolve(strict=True)
    if requested.parent.is_symlink() or not parent.is_dir():
        raise _RuntimeConflictError("runtime parent is unsafe")
    runtime = parent / requested.name
    if _paths_overlap(runtime, project) or _paths_overlap(runtime, fixture):
        raise _RuntimeConflictError("runtime path overlaps immutable inputs")
    runtime.mkdir(mode=0o700)
    return runtime


def _prepare_case(
    root: Path,
    fixture: SyntheticFastqFixture,
    *,
    syntax_only: bool,
) -> Path:
    root.mkdir(mode=0o700)
    assets = root / "assets"
    assets.mkdir(mode=0o700)
    inputs = root / "inputs"
    inputs.mkdir(mode=0o700)
    for row in fixture.rows:
        _snapshot_read(inputs, fixture.root, row.read1, row.read1_payload)
        if row.read2 is not None and row.read2_payload is not None:
            _snapshot_read(inputs, fixture.root, row.read2, row.read2_payload)
    _write_exclusive(
        assets / "samplesheet.csv",
        render_synthetic_samplesheet(fixture, source_root=inputs),
    )
    _write_exclusive(
        root / "test.config",
        _SYNTAX_CONFIG if syntax_only else _NO_CONTAINER_CONFIG,
    )
    return root


def _snapshot_read(root: Path, fixture_root: Path, source: Path, payload: bytes) -> None:
    relative = source.relative_to(fixture_root)
    destination = root.joinpath(*relative.parts)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_exclusive_bytes(destination, payload)


def _restricted_environment(
    runtime: Path,
    parent: Mapping[str, str],
) -> dict[str, str]:
    nxf_home = runtime / "nxf-home"
    temporary = runtime / "tmp"
    nxf_home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "NXF_ANSI_LOG": "false",
        "NXF_HOME": str(nxf_home),
        "NXF_OFFLINE": "true",
        "PATH": parent.get("PATH", os.defpath),
        "TMPDIR": str(temporary),
    }
    java_home = parent.get("JAVA_HOME")
    if java_home and "\x00" not in java_home:
        environment["JAVA_HOME"] = java_home
    return environment


def _nextflow_run_argv(
    executable: str,
    project: Path,
    case_root: Path,
    log_path: Path,
    *,
    source_root: Path,
    preview: bool,
    stub: bool,
    add_config: bool,
) -> tuple[str, ...]:
    arguments: list[str] = [executable]
    if add_config:
        arguments.extend(("-c", str(case_root / "test.config")))
    arguments.extend(("-log", str(log_path), "run", str(project), "-profile", "local"))
    if preview:
        arguments.append("-preview")
    if stub:
        arguments.append("-stub-run")
    arguments.extend(
        (
            "-work-dir",
            str(case_root / "work"),
            "--samplesheet",
            str(case_root / "assets" / "samplesheet.csv"),
            "--source_root",
            str(source_root),
            "--output_dir",
            str(case_root / "results"),
        )
    )
    return tuple(arguments)


def _write_exclusive(path: Path, text: str) -> None:
    _write_exclusive_bytes(path, text.encode("utf-8"))


def _write_exclusive_bytes(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise OSError("test artifact write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_limits(timeout_seconds: float, output_limit_bytes: int) -> None:
    if not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 3_600:
        raise ValueError("timeout_seconds must be between 1 and 3600")
    if not 1_024 <= output_limit_bytes <= 16 * 1024 * 1024:
        raise ValueError("output_limit_bytes must be between 1 KiB and 16 MiB")


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _check_from_result(
    name: str,
    result: CommandResult,
    failure_code: WorkflowTestCode,
    failure_message: str,
) -> WorkflowCheck:
    if result.timed_out:
        return _failed_check(
            name,
            WorkflowTestCode.COMMAND_TIMEOUT,
            "A workflow test command exceeded its configured deadline.",
            ("Increase the bounded test timeout only after reviewing the generated project.",),
            return_code=result.return_code,
        )
    if result.output_limit_exceeded:
        return _failed_check(
            name,
            WorkflowTestCode.COMMAND_OUTPUT_LIMIT,
            "A workflow test command exceeded the bounded output limit.",
            ("Inspect local logs and correct unexpectedly verbose or looping workflow code.",),
            return_code=result.return_code,
        )
    if result.return_code != 0:
        return _failed_check(
            name,
            failure_code,
            failure_message,
            ("Inspect the bounded local Nextflow log; no real-data run was attempted.",),
            return_code=result.return_code,
        )
    return _passed_check(name, "The bounded command completed successfully.", result.return_code)


def _passed_check(name: str, message: str, return_code: int | None = None) -> WorkflowCheck:
    return WorkflowCheck(
        name=name,
        status=WorkflowTestStatus.PASSED,
        code=WorkflowTestCode.OK,
        return_code=return_code,
        message=message,
    )


def _failed_check(
    name: str,
    code: WorkflowTestCode,
    message: str,
    remediation: tuple[str, ...],
    *,
    return_code: int | None = None,
) -> WorkflowCheck:
    return WorkflowCheck(
        name=name,
        status=WorkflowTestStatus.FAILED,
        code=code,
        return_code=return_code,
        message=message,
        remediation=remediation,
    )


def _blocked_check(
    name: str,
    code: WorkflowTestCode,
    message: str,
    remediation: tuple[str, ...],
) -> WorkflowCheck:
    return WorkflowCheck(
        name=name,
        status=WorkflowTestStatus.BLOCKED,
        code=code,
        message=message,
        remediation=remediation,
    )


def _terminal_report(
    mode: Literal["validate", "stub", "e2e"],
    terminal: WorkflowCheck,
    prior_checks: Sequence[WorkflowCheck],
    *,
    project: _ProjectContext | None = None,
    outputs: tuple[str, ...] = (),
    cause: BaseException | None = None,
) -> WorkflowTestReport:
    del cause
    return WorkflowTestReport(
        mode=mode,
        status=terminal.status,
        code=terminal.code,
        layout=None if project is None else project.planned.spec.input.layout,
        trimming_enabled=(
            None if project is None else project.planned.spec.parameters.trimming.enabled
        ),
        checks=tuple((*prior_checks, terminal)),
        outputs=outputs,
        remediation=terminal.remediation,
    )


__all__ = ["WorkflowTestRunner"]
