"""Adversarial tests for the separately installed dormant compute worker."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import bioexec.compute_worker as worker_module
from bioexec.compute_worker import (
    ComputeWorkerCommitUnknown,
    ComputeWorkerError,
    WorkerInvocation,
    parse_worker_argv,
    run_worker,
)
from bioexec.scheduler_preflight import (
    COMPUTE_CHECK_NAMES,
    ComputePreflightEvidence,
    canonical_evidence_bytes,
    canonical_manifest_bytes,
    decode_compute_evidence,
    input_set_hash,
    parse_compute_manifest,
)
from bioexec.slurm import SlurmSchedulerPolicy, scheduler_policy_hash

_PROFILE_HASH = "a" * 64
_MARKER = "f" * 64
_JOB_ID = "12345"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_regular(path: Path, payload: bytes, mode: int) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


@dataclass
class WorkerFixture:
    root: Path
    attempt: Path
    manifest_path: Path
    evidence_path: Path
    worker_path: Path
    python_path: Path
    input_path: Path
    deploy_dir: Path
    work_dir: Path
    output_dir: Path
    cache_dir: Path
    manifest_value: dict[str, Any]
    invocation: WorkerInvocation
    environment: dict[str, str]
    commands: list[tuple[str, ...]]

    def run(self) -> ComputePreflightEvidence:
        def command_runner(
            argv: tuple[str, ...],
            _cwd: Path,
            _environment: object,
            _timeout: float,
            _limit: int,
        ) -> worker_module._CommandResult:
            self.commands.append(argv)
            output = b"Version 24.10.0\n" if "-jar" in argv else b"runtime ok\n"
            return worker_module._CommandResult(0, output, b"", False, False)

        return run_worker(
            self.invocation,
            environment=self.environment,
            worker_path=str(self.worker_path),
            python_path=str(self.python_path),
            command_runner=command_runner,
        )

    def rewrite_manifest(self) -> None:
        manifest = parse_compute_manifest(self.manifest_value)
        self.manifest_path.write_bytes(canonical_manifest_bytes(manifest))
        self.manifest_path.chmod(0o600)
        self.invocation = WorkerInvocation(
            contract_version="1.0",
            manifest_path=str(self.manifest_path),
            manifest_sha256=hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
            worker_sha256=_sha256(self.worker_path),
            evidence_path=str(self.evidence_path),
        )


@pytest.fixture
def worker_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WorkerFixture:
    tmp_path.chmod(0o700)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o700)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    read_dir = tmp_path / "read"
    read_dir.mkdir(mode=0o700)
    deploy_root = tmp_path / "deploy"
    deploy_root.mkdir(mode=0o700)
    work_root = tmp_path / "work"
    work_root.mkdir(mode=0o700)
    output_root = tmp_path / "output"
    output_root.mkdir(mode=0o700)
    cache_root = tmp_path / "cache"
    cache_root.mkdir(mode=0o700)
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    attempt = state_root / "scheduler-preflights-v1" / "preflight-1"
    attempt.parent.mkdir(mode=0o700)
    attempt.mkdir(mode=0o700)

    python_path = bin_dir / "python3"
    java_path = bin_dir / "java"
    nextflow_path = bin_dir / "nextflow"
    apptainer_path = bin_dir / "apptainer"
    worker_path = bin_dir / "bioexec-compute-preflight"
    for path in (python_path, java_path, nextflow_path, apptainer_path, worker_path):
        _write_regular(path, f"synthetic:{path.name}\n".encode("ascii"), 0o755)

    nextflow_jar = runtime_dir / "nextflow-24.10.0-one.jar"
    _write_regular(nextflow_jar, b"synthetic nextflow jar\n", 0o444)
    input_path = read_dir / "sample_R1.fastq.gz"
    _write_regular(input_path, b"synthetic fastq\n", 0o444)
    cache_dir = cache_root / "job-1"
    cache_dir.mkdir(mode=0o700)
    sif_paths = (cache_root / "fastqc.sif", cache_root / "multiqc.sif")
    for index, path in enumerate(sif_paths, start=1):
        _write_regular(path, f"synthetic sif {index}\n".encode("ascii"), 0o444)

    policy_mapping: dict[str, Any] = {
        "partition": "compute",
        "account": "bioinfo",
        "qos": "normal",
        "time_limit": "00:15:00",
        "cpus_per_task": 8,
        "memory_mib": 4096,
        "submit_timeout_seconds": 30,
        "status_poll_seconds": 5,
        "max_pending_seconds": 60,
    }
    policy = SlurmSchedulerPolicy.from_mapping(policy_mapping)
    artifact_hashes = {
        "dataset_manifest": "1" * 64,
        "pipeline_spec": "2" * 64,
        "execution_plan": "3" * 64,
        "software_lock": "4" * 64,
        "execution_profile": _PROFILE_HASH,
    }
    project_hash = _canonical_hash(
        {
            "dataset_manifest": artifact_hashes["dataset_manifest"],
            "execution_plan": artifact_hashes["execution_plan"],
            "pipeline_spec": artifact_hashes["pipeline_spec"],
            "software_lock": artifact_hashes["software_lock"],
        }
    )
    execution_paths = (str(input_path),)
    manifest_path = attempt / "manifest.json"
    evidence_path = attempt / "evidence.json"
    manifest_value: dict[str, Any] = {
        "manifest_version": "1.1",
        "preflight_id": "preflight-1",
        "profile_version": "2.0",
        "profile_id": "hpc01-slurm",
        "profile_hash": _PROFILE_HASH,
        "scheduler_policy_hash": scheduler_policy_hash(policy),
        "scheduler_policy": policy_mapping,
        "compute_runtime": {
            "python_executable": str(python_path),
            "python_sha256": _sha256(python_path),
            "java_executable": str(java_path),
            "java_sha256": _sha256(java_path),
            "nextflow_executable": str(nextflow_path),
            "nextflow_sha256": _sha256(nextflow_path),
            "nextflow_version": "24.10.0",
            "nextflow_jar": str(nextflow_jar),
            "nextflow_jar_sha256": _sha256(nextflow_jar),
            "apptainer_executable": str(apptainer_path),
            "apptainer_sha256": _sha256(apptainer_path),
            "command_timeout_seconds": 1.0,
            "max_command_output_bytes": 4096,
        },
        "project_hash": project_hash,
        "artifact_hashes": artifact_hashes,
        "source_host": "source-host",
        "execution_host": "compute-host",
        "host_relation": "shared",
        "source_paths": [str(input_path)],
        "execution_paths": list(execution_paths),
        "path_mapping": [
            {
                "source_prefix": str(read_dir),
                "execution_prefix": str(read_dir),
            }
        ],
        "input_set_hash": input_set_hash(execution_paths),
        "deploy_dir": str(deploy_root / "project-1"),
        "work_dir": str(work_root / "run-1"),
        "output_dir": str(output_root / "run-1"),
        "cache_dir": str(cache_dir),
        "containers": [
            {
                "name": "fastqc",
                "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
                "digest": f"sha256:{'5' * 64}",
                "local_path": str(sif_paths[0]),
                "file_sha256": _sha256(sif_paths[0]),
            },
            {
                "name": "multiqc",
                "image": "quay.io/biocontainers/multiqc:1.27.1--pyhdfd78af_0",
                "digest": f"sha256:{'7' * 64}",
                "local_path": str(sif_paths[1]),
                "file_sha256": _sha256(sif_paths[1]),
            },
        ],
        "minimum_free_bytes": 1,
        "network_disabled": True,
        "resume_run_id": None,
        "resume_directory_identities": None,
        "preflight_ttl_seconds": 900,
        "worker": {
            "contract_version": "1.0",
            "executable": str(worker_path),
            "executable_sha256": _sha256(worker_path),
            "manifest_path": str(manifest_path),
            "evidence_path": str(evidence_path),
        },
    }
    manifest = parse_compute_manifest(manifest_value)
    manifest_path.write_bytes(canonical_manifest_bytes(manifest))
    manifest_path.chmod(0o600)
    invocation = WorkerInvocation(
        contract_version="1.0",
        manifest_path=str(manifest_path),
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        worker_sha256=_sha256(worker_path),
        evidence_path=str(evidence_path),
    )
    environment = {
        "SLURM_JOB_ID": _JOB_ID,
        "SLURM_JOB_NAME": _MARKER,
        "SLURM_JOB_NUM_NODES": "1",
        "SLURM_NTASKS": "1",
        "SLURM_CPUS_PER_TASK": "8",
        "SLURM_MEM_PER_NODE": "4096",
        "SLURM_JOB_START_TIME": "1700000000",
        "SLURM_JOB_END_TIME": "1700000900",
        "SLURM_JOB_PARTITION": "compute",
        "SLURM_JOB_ACCOUNT": "bioinfo",
        "SLURM_JOB_QOS": "normal",
    }
    monkeypatch.chdir(attempt)
    return WorkerFixture(
        root=tmp_path,
        attempt=attempt,
        manifest_path=manifest_path,
        evidence_path=evidence_path,
        worker_path=worker_path,
        python_path=python_path,
        input_path=input_path,
        deploy_dir=Path(manifest.deploy_dir),
        work_dir=Path(manifest.work_dir),
        output_dir=Path(manifest.output_dir),
        cache_dir=cache_dir,
        manifest_value=manifest_value,
        invocation=invocation,
        environment=environment,
        commands=[],
    )


def test_worker_publishes_complete_canonical_passed_evidence(
    worker_fixture: WorkerFixture,
) -> None:
    evidence = worker_fixture.run()

    assert evidence.status == "passed"
    assert tuple(check.name for check in evidence.checks) == COMPUTE_CHECK_NAMES
    assert all(check.code == "OK" for check in evidence.checks)
    assert worker_fixture.evidence_path.read_bytes() == canonical_evidence_bytes(evidence)
    metadata = worker_fixture.evidence_path.lstat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    assert any("--network" in argv for argv in worker_fixture.commands)
    assert any("-jar" in argv for argv in worker_fixture.commands)


def test_environmental_check_failure_is_complete_evidence_not_worker_failure(
    worker_fixture: WorkerFixture,
) -> None:
    worker_fixture.input_path.unlink()

    evidence = worker_fixture.run()

    assert evidence.status == "failed"
    failed = [check for check in evidence.checks if check.status == "failed"]
    assert [check.name for check in failed] == ["input_paths"]
    assert failed[0].code == "INPUT_PATH_UNAVAILABLE"
    assert worker_fixture.evidence_path.is_file()


def test_allocation_policy_binds_the_effective_slurm_time_limit(
    worker_fixture: WorkerFixture,
) -> None:
    worker_fixture.environment["SLURM_JOB_END_TIME"] = "1700000960"

    evidence = worker_fixture.run()

    failed = [check for check in evidence.checks if check.status == "failed"]
    assert [(check.name, check.code) for check in failed] == [
        ("allocation_policy", "ALLOCATION_POLICY_MISMATCH")
    ]


@pytest.mark.parametrize("check_name", COMPUTE_CHECK_NAMES)
def test_every_fixed_check_failure_still_publishes_complete_evidence(
    worker_fixture: WorkerFixture,
    monkeypatch: pytest.MonkeyPatch,
    check_name: str,
) -> None:
    def fail_check(_context: object) -> object:
        raise worker_module._CheckFailure("SYNTHETIC_CHECK_FAILURE")

    monkeypatch.setattr(worker_module, f"_check_{check_name}", fail_check)

    evidence = worker_fixture.run()

    assert evidence.status == "failed"
    assert tuple(check.name for check in evidence.checks) == COMPUTE_CHECK_NAMES
    failed = [check for check in evidence.checks if check.status == "failed"]
    assert [(check.name, check.code) for check in failed] == [
        (check_name, "SYNTHETIC_CHECK_FAILURE")
    ]


def test_main_returns_zero_for_complete_failed_evidence(
    worker_fixture: WorkerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_fixture.input_path.unlink()
    invocation = worker_fixture.invocation
    argv = [
        "--contract-version=1.0",
        f"--manifest={invocation.manifest_path}",
        f"--manifest-sha256={invocation.manifest_sha256}",
        f"--worker-sha256={invocation.worker_sha256}",
        f"--evidence={invocation.evidence_path}",
    ]
    monkeypatch.setattr(worker_module.sys, "argv", [str(worker_fixture.worker_path), *argv])
    monkeypatch.setattr(worker_module.sys, "executable", str(worker_fixture.python_path))
    for key, value in worker_fixture.environment.items():
        monkeypatch.setenv(key, value)

    assert worker_module.main(argv) == 0
    assert decode_compute_evidence(worker_fixture.evidence_path.read_bytes()).status == "failed"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--contract-version=1.0"],
        [
            "--contract-version=1.0",
            "--manifest=/private/manifest.json",
            "--manifest-sha256=" + "a" * 64,
            "--worker-sha256=" + "b" * 64,
            "--evidence=/other/evidence.json",
        ],
        [
            "--contract-version=1.0",
            "--manifest=/private/manifest.json",
            "--manifest-sha256=" + "a" * 64,
            "--worker-sha256=" + "b" * 64,
            "--evidence=/private/evidence.json",
            "--extra=true",
        ],
    ],
)
def test_worker_cli_rejects_missing_extra_and_cross_directory_arguments(
    argv: list[str],
) -> None:
    with pytest.raises(ComputeWorkerError):
        parse_worker_argv(argv)


def test_worker_cli_accepts_only_exact_ordered_template_arguments(
    worker_fixture: WorkerFixture,
) -> None:
    invocation = worker_fixture.invocation
    argv = [
        "--contract-version=1.0",
        f"--manifest={invocation.manifest_path}",
        f"--manifest-sha256={invocation.manifest_sha256}",
        f"--worker-sha256={invocation.worker_sha256}",
        f"--evidence={invocation.evidence_path}",
    ]
    assert parse_worker_argv(argv) == invocation

    argv[0], argv[1] = argv[1], argv[0]
    with pytest.raises(ComputeWorkerError):
        parse_worker_argv(argv)


def test_manifest_mode_hardlink_and_hash_mismatch_fail_before_checks(
    worker_fixture: WorkerFixture,
) -> None:
    worker_fixture.manifest_path.chmod(0o640)
    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()

    worker_fixture.manifest_path.chmod(0o600)
    alias = worker_fixture.attempt / "manifest-alias.json"
    os.link(worker_fixture.manifest_path, alias)
    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()
    alias.unlink()

    worker_fixture.invocation = WorkerInvocation(
        **{
            **worker_fixture.invocation.__dict__,
            "manifest_sha256": "e" * 64,
        }
    )
    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()


def test_symlinked_manifest_is_rejected_without_creating_evidence(
    worker_fixture: WorkerFixture,
) -> None:
    target = worker_fixture.attempt / "real-manifest.json"
    worker_fixture.manifest_path.rename(target)
    worker_fixture.manifest_path.symlink_to(target)

    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()
    assert not worker_fixture.evidence_path.exists()


def test_existing_evidence_is_never_overwritten(worker_fixture: WorkerFixture) -> None:
    worker_fixture.evidence_path.write_bytes(b"existing\n")
    worker_fixture.evidence_path.chmod(0o600)

    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()
    assert worker_fixture.evidence_path.read_bytes() == b"existing\n"


def test_worker_and_interpreter_hashes_are_rechecked(worker_fixture: WorkerFixture) -> None:
    worker_fixture.worker_path.write_bytes(b"changed worker\n")
    worker_fixture.worker_path.chmod(0o755)
    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()

    worker_fixture.manifest_value["worker"]["executable_sha256"] = _sha256(
        worker_fixture.worker_path
    )
    worker_fixture.rewrite_manifest()
    worker_fixture.python_path.write_bytes(b"changed python\n")
    worker_fixture.python_path.chmod(0o755)
    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()


def test_read_only_input_traversal_allows_a_non_service_data_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "data-owner.fastq.gz"
    input_path.write_bytes(b"synthetic reads\n")
    input_path.chmod(0o440)
    actual_owner = input_path.stat().st_uid
    monkeypatch.setattr(worker_module.os, "geteuid", lambda: actual_owner + 100_000)

    observation = worker_module._observe_regular(
        str(input_path),
        maximum_bytes=1024,
        hash_contents=False,
        trusted_owner=False,
        require_executable=False,
        require_no_group_world_write=True,
    )

    assert observation["inode"] == input_path.stat().st_ino
    assert observation["size"] == len(b"synthetic reads\n")


def test_wrong_cwd_fails_before_worker_side_effects(
    worker_fixture: WorkerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(worker_fixture.root)
    with pytest.raises(ComputeWorkerError):
        worker_fixture.run()
    assert not worker_fixture.evidence_path.exists()


def test_resume_requires_exact_private_directory_identities(
    worker_fixture: WorkerFixture,
) -> None:
    identities: dict[str, dict[str, int]] = {}
    for role, path in (
        ("deploy", worker_fixture.deploy_dir),
        ("work", worker_fixture.work_dir),
        ("output", worker_fixture.output_dir),
    ):
        path.mkdir(mode=0o700)
        metadata = path.lstat()
        identities[role] = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "owner": metadata.st_uid,
            "group": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
        }
    worker_fixture.manifest_value["resume_run_id"] = "run-previous"
    worker_fixture.manifest_value["resume_directory_identities"] = identities
    worker_fixture.rewrite_manifest()

    assert worker_fixture.run().status == "passed"


def test_resume_identity_mismatch_is_failed_evidence(worker_fixture: WorkerFixture) -> None:
    identities: dict[str, dict[str, int]] = {}
    for role, path in (
        ("deploy", worker_fixture.deploy_dir),
        ("work", worker_fixture.work_dir),
        ("output", worker_fixture.output_dir),
    ):
        path.mkdir(mode=0o700)
        metadata = path.lstat()
        identities[role] = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "owner": metadata.st_uid,
            "group": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
        }
    identities["work"]["inode"] += 1
    worker_fixture.manifest_value["resume_run_id"] = "run-previous"
    worker_fixture.manifest_value["resume_directory_identities"] = identities
    worker_fixture.rewrite_manifest()

    evidence = worker_fixture.run()
    failed = {check.name: check.code for check in evidence.checks if check.status == "failed"}
    assert failed["work_storage"] == "WORK_STORAGE_UNAVAILABLE"


def test_fixed_command_runner_bounds_timeout_and_output(tmp_path: Path) -> None:
    output = worker_module._run_command(
        (sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"),
        tmp_path,
        {"LANG": "C", "LC_ALL": "C"},
        2.0,
        1024,
    )
    assert output.output_limit_exceeded is True
    assert len(output.stdout) + len(output.stderr) <= 1024

    timeout = worker_module._run_command(
        (sys.executable, "-c", "import time; time.sleep(10)"),
        tmp_path,
        {"LANG": "C", "LC_ALL": "C"},
        0.05,
        1024,
    )
    assert timeout.timed_out is True


def test_command_timeout_kills_group_after_leader_exits(tmp_path: Path) -> None:
    terminated = tmp_path / "descendant-terminated"
    code = (
        "import os, signal, time\n"
        "child = os.fork()\n"
        "if child:\n"
        "    os._exit(0)\n"
        f"marker = {str(terminated)!r}\n"
        "def stop(_signum, _frame):\n"
        "    open(marker, 'wb').close()\n"
        "    os._exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "print(os.getpid(), flush=True)\n"
        "time.sleep(10)\n"
    )
    script = tmp_path / "escaped-descendant.py"
    script.write_text(code, encoding="utf-8")

    started = time.monotonic()
    result = worker_module._run_command(
        (sys.executable, str(script)),
        tmp_path,
        {"LANG": "C", "LC_ALL": "C"},
        5.0,
        1024,
    )
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert elapsed < 2.0
    assert result.stdout.strip().isdigit()
    deadline = time.monotonic() + 1.0
    while not terminated.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert terminated.is_file()


def test_evidence_fsync_failure_is_commit_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    descriptor = os.open(tmp_path, worker_module._DIRECTORY_FLAGS)
    real_fsync = os.fsync
    calls = 0

    def fail_file_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(worker_module.os, "fsync", fail_file_fsync)
    try:
        with pytest.raises(ComputeWorkerCommitUnknown):
            worker_module._publish_evidence(descriptor, "evidence.json", b"{}")
    finally:
        os.close(descriptor)
    assert (tmp_path / "evidence.json").exists()


def test_worker_source_has_only_the_fixed_subprocess_surface() -> None:
    source_path = Path(__file__).parents[1] / "src" / "bioexec" / "compute_worker.py"
    source = source_path.read_text(encoding="utf-8")
    syntax = ast.parse(source, filename=str(source_path))

    assert "shell=True" not in source
    assert "os.system" not in source
    assert "subprocess.run" not in source
    assert "subprocess.call" not in source
    assert "subprocess.check_" not in source
    assert all(
        not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
        or node.func.id not in {"eval", "exec", "compile", "__import__"}
        for node in ast.walk(syntax)
    )
    popen_calls = [
        node
        for node in ast.walk(syntax)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "Popen"
    ]
    assert len(popen_calls) == 1
    keywords = {item.arg: item.value for item in popen_calls[0].keywords}
    assert isinstance(keywords["shell"], ast.Constant) and keywords["shell"].value is False
    assert (
        isinstance(keywords["start_new_session"], ast.Constant)
        and keywords["start_new_session"].value is True
    )
    assert {"cwd", "env", "stdin", "stdout", "stderr", "close_fds"} <= set(keywords)


def test_version_one_import_graph_does_not_load_compute_worker() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "import bioexec.main, bioexec.config, bioexec.protocol\n"
        "import bioexec.preflight, bioexec.deployment, bioexec.runner\n"
        "import bioexec.state, bioexec.commands\n"
        "assert 'bioexec.compute_worker' not in sys.modules\n"
    )
    python = Path("/usr/bin/python3")
    completed = subprocess.run(
        [str(python if python.exists() else Path(sys.executable)), "-B", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
