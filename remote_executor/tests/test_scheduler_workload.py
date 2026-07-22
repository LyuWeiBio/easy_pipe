"""Adversarial tests for the dormant fixed scheduler workload contract."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from bioexec.scheduler_preflight import parse_compute_manifest, prepare_preflight
from bioexec.scheduler_run import SchedulerStartPermitError, consume_start_permit
from bioexec.scheduler_state import SchedulerStateSnapshot
from bioexec.scheduler_workload import (
    SchedulerWorkloadError,
    SchedulerWorkloadPlan,
    build_nextflow_argv,
    canonical_workload_plan_bytes,
    prepare_scheduler_workload,
    render_nextflow_overlay,
    render_workload_batch,
)
from bioexec.slurm import SlurmSchedulerPolicy, scheduler_policy_hash

from .test_scheduler_run import RunFixture
from .test_scheduler_run import run_fixture as run_fixture
from .test_scheduler_state import state_fixture as state_fixture

_ENVIRONMENT_KEYS = {
    "LANG",
    "LC_ALL",
    "PATH",
    "HOME",
    "JAVA_CMD",
    "NXF_ANSI_LOG",
    "NXF_CACHE_DIR",
    "NXF_OFFLINE",
    "NXF_DISABLE_CHECK_LATEST",
    "NXF_HOME",
    "NXF_BIN",
    "NXF_VER",
    "NXF_TEMP",
    "TMPDIR",
    "APPTAINER_CACHEDIR",
    "APPTAINER_CONFIGDIR",
    "SINGULARITY_CACHEDIR",
    "SINGULARITY_CONFIGDIR",
}


@pytest.fixture
def workload(
    run_fixture: RunFixture,
) -> tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan]:
    run = run_fixture.run_store.reserve_and_consume(run_fixture.verified)
    preflight = run_fixture.run_store.load_consumed_preflight(run)
    return (
        run_fixture,
        preflight,
        prepare_scheduler_workload(run_fixture.state.config, run, preflight),
    )


def test_workload_plan_is_byte_reproducible_and_secret_free(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
) -> None:
    fixture, preflight, first = workload
    run = fixture.run_store.load(first.run_id)
    repeated = prepare_scheduler_workload(fixture.state.config, run, preflight)

    assert first == repeated
    assert first.batch_bytes == repeated.batch_bytes
    assert first.overlay_bytes == repeated.overlay_bytes
    assert first.submission_marker == repeated.submission_marker
    assert hashlib.sha256(canonical_workload_plan_bytes(first)).hexdigest() == first.binding_sha256
    assert (
        first.command_sha256
        == hashlib.sha256(
            json.dumps(
                list(first.nextflow_argv),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
    )
    serialized = first.batch_bytes + first.overlay_bytes + canonical_workload_plan_bytes(first)
    assert fixture.verified._preflight_token.encode("ascii") not in serialized
    assert fixture.signature.encode("ascii") not in serialized
    assert fixture.state.config.contract.approval_hmac_key.hex().encode("ascii") not in serialized
    assert "batch_bytes" not in repr(first)
    assert "overlay_bytes" not in repr(first)


def test_batch_execs_only_the_hash_bound_bootstrap(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
) -> None:
    _fixture, _preflight, plan = workload
    script = plan.batch_bytes.decode("utf-8")

    assert script.startswith("#!/bin/sh\nset -eu\numask 077\nexec ")
    assert script.count("exec ") == 1
    assert "bioexec-compute-bootstrap" in script
    assert " -I" not in script  # every argument is independently single-quoted
    assert "nextflow" not in script.casefold()
    assert "sbatch" not in script.casefold()
    assert "--wrap" not in script
    assert (
        subprocess.run(
            ["/bin/sh", "-n"],
            input=plan.batch_bytes,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def test_nextflow_argv_environment_and_submit_surface_are_closed(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
) -> None:
    fixture, _preflight, plan = workload
    manifest = fixture.state.prepared.manifest

    assert plan.nextflow_argv == (
        manifest.compute_runtime.nextflow_executable,
        "-C",
        plan.overlay_path,
        "-log",
        f"{plan.working_directory}/nextflow.log",
        "run",
        manifest.deploy_dir,
        "-profile",
        "local",
        "-work-dir",
        manifest.work_dir,
        "--output_dir",
        manifest.output_dir,
        "--samplesheet",
        f"{manifest.deploy_dir}/assets/samplesheet.csv",
        "-name",
        "ep-" + hashlib.sha256(plan.run_id.encode("ascii")).hexdigest(),
    )
    assert set(plan.environment) == _ENVIRONMENT_KEYS
    assert plan.environment["NXF_BIN"] == manifest.compute_runtime.nextflow_jar
    assert plan.environment["JAVA_CMD"] == manifest.compute_runtime.java_executable
    assert plan.environment["NXF_CACHE_DIR"] == f"{manifest.work_dir}/.easy-pipe-nextflow-cache-v1"
    assert plan.environment["APPTAINER_CACHEDIR"] == manifest.cache_dir
    assert plan.environment["NXF_OFFLINE"] == "true"
    assert plan.environment["NXF_DISABLE_CHECK_LATEST"] == "true"
    assert not {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "AWS_SECRET_ACCESS_KEY",
        "LD_PRELOAD",
        "JAVA_TOOL_OPTIONS",
        "NXF_OPTS",
    } & set(plan.environment)
    with pytest.raises(TypeError):
        plan.environment["NXF_OPTS"] = "-Dunsafe=true"  # type: ignore[index]

    assert plan.submit_argv[0] == str(fixture.state.config.executables["sbatch"].path)
    assert plan.submit_argv[1:6] == (
        "--parsable",
        "--hold",
        "--export=NIL",
        "--no-requeue",
        "--nodes=1",
    )
    assert all("--wrap" not in argument for argument in plan.submit_argv)
    assert dict(plan.submit_environment) == {
        "HOME": str(fixture.run_directory),
        "LANG": "C",
        "LC_ALL": "C",
    }


def test_overlay_forces_local_offline_apptainer_and_policy_limits(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
) -> None:
    fixture, _preflight, plan = workload
    text = plan.overlay_bytes.decode("utf-8")
    policy = fixture.state.config.contract.scheduler

    assert text.startswith(f"includeConfig '{fixture.deployment.deployment_dir}/nextflow.config'\n")
    assert "process.executor = 'local'" in text
    assert f"executor.cpus = {policy.cpus_per_task}" in text
    assert f"executor.memory = '{policy.memory_mib} MB'" in text
    assert "executor.queueSize = 1" in text
    assert "apptainer.enabled = true" in text
    assert "docker.enabled = false" in text
    assert "singularity.enabled = false" in text
    assert "--containall --no-home --cleanenv --net --network none" in text
    assert "withLabel: 'fastqc_raw'" in text
    assert "withLabel: 'fastqc_post_trim'" in text
    assert "withLabel: 'multiqc'" in text
    admitted_labels = {"fastqc_raw", "fastqc_post_trim", "multiqc"}
    if any(item.name == "fastp" for item in fixture.state.prepared.manifest.containers):
        admitted_labels.add("fastp")
    assert text.count("executor = 'local'") == 1 + len(admitted_labels)
    for container in fixture.state.prepared.manifest.containers:
        assert container.local_path in text


def test_start_intent_and_live_permit_bind_exact_workload_hashes(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
) -> None:
    fixture, preflight, plan = workload
    snapshot = fixture.run_store.load(plan.run_id)

    with fixture.run_store.claim_start(
        snapshot,
        preflight,
        lambda: None,
        workload=plan,
    ) as permit:
        assert permit.workload_binding_sha256 == plan.binding_sha256
        assert permit.workload_batch_sha256 == plan.batch_sha256
        consume_start_permit(permit, snapshot, plan)

    intent = json.loads((fixture.run_directory / "start.intent.json").read_text("ascii"))
    assert intent["schema_version"] == "1.1"
    assert intent["workload_binding_sha256"] == plan.binding_sha256
    assert intent["workload_batch_sha256"] == plan.batch_sha256


def test_live_permit_recomputes_the_same_plan_before_consumption(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
) -> None:
    fixture, preflight, plan = workload
    snapshot = fixture.run_store.load(plan.run_id)

    with fixture.run_store.claim_start(
        snapshot,
        preflight,
        lambda: None,
        workload=plan,
    ) as permit:
        changed = copy.copy(plan)
        object.__setattr__(changed, "batch_bytes", plan.batch_bytes + b"# changed\n")
        with pytest.raises(SchedulerStartPermitError):
            consume_start_permit(permit, snapshot, changed)
        consume_start_permit(permit, snapshot, plan)


@pytest.mark.parametrize("digest", ["d" * 64, "0" * 64, "A" * 64, "short"])
def test_start_claim_rejects_tampered_workload_before_intent(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
    digest: str,
) -> None:
    fixture, preflight, plan = workload
    snapshot = fixture.run_store.load(plan.run_id)
    changed = copy.copy(plan)
    object.__setattr__(changed, "binding_sha256", digest)

    with (
        pytest.raises(ValueError),
        fixture.run_store.claim_start(
            snapshot,
            preflight,
            lambda: None,
            workload=changed,
        ),
    ):
        pytest.fail("a tampered workload plan must not yield a permit")
    assert not (fixture.run_directory / "start.intent.json").exists()


def test_resume_binds_the_prior_named_session_in_the_shared_cache(
    run_fixture: RunFixture,
) -> None:
    initial = run_fixture.state.prepared
    value = copy.deepcopy(initial.manifest.as_mapping())
    value["resume_run_id"] = "run-previous"
    value["resume_directory_identities"] = {
        role: {"device": index, "inode": index + 10, "owner": 501, "group": 20, "mode": 0o700}
        for index, role in enumerate(("deploy", "output", "work"), start=1)
    }
    resume = prepare_preflight(parse_compute_manifest(value))
    runtime_directory = "/srv/biopipe/private-state/scheduler-runs-v1/run-2/runtime-v1"

    initial_argv = build_nextflow_argv(initial, "run-2", runtime_directory)
    resume_argv = build_nextflow_argv(resume, "run-2", runtime_directory)

    expected_session = "ep-" + hashlib.sha256(b"run-previous").hexdigest()
    assert resume_argv == (*initial_argv, "-resume", expected_session)
    assert resume_argv.count("-resume") == 1
    assert resume_argv[-1] != resume_argv[-3]


@pytest.mark.parametrize(
    "run_id,runtime_directory",
    [
        ("run-2", "relative/scheduler-runs-v1/run-2/runtime-v1"),
        ("run-2", "/srv/state/scheduler-runs-v1/run-other/runtime-v1"),
        ("run-2", "/srv/state/other-runs/run-2/runtime-v1"),
        ("run-2", "/srv/state/scheduler-runs-v1/run-2/runtime-v2"),
        ("run/2", "/srv/state/scheduler-runs-v1/run-2/runtime-v1"),
        ("run-2", 42),
    ],
)
def test_nextflow_argv_rejects_unbound_runtime_directory(
    run_fixture: RunFixture,
    run_id: str,
    runtime_directory: object,
) -> None:
    with pytest.raises(SchedulerWorkloadError, match=r"run identifier|runtime directory"):
        build_nextflow_argv(
            run_fixture.state.prepared,
            run_id,
            runtime_directory,  # type: ignore[arg-type]
        )


def test_overlay_hash_changes_with_policy_or_sif_binding(run_fixture: RunFixture) -> None:
    initial = run_fixture.state.prepared
    initial_bytes = render_nextflow_overlay(initial)

    changed_policy = copy.deepcopy(initial.manifest.as_mapping())
    changed_policy["scheduler_policy"]["cpus_per_task"] -= 1
    parsed_policy = SlurmSchedulerPolicy.from_mapping(changed_policy["scheduler_policy"])
    changed_policy["scheduler_policy_hash"] = scheduler_policy_hash(parsed_policy)
    policy_state = prepare_preflight(parse_compute_manifest(changed_policy))

    changed_sif = copy.deepcopy(initial.manifest.as_mapping())
    changed_sif["containers"][0]["local_path"] = str(
        Path(changed_sif["containers"][0]["local_path"]).with_name("changed-fastqc.sif")
    )
    sif_state = prepare_preflight(parse_compute_manifest(changed_sif))

    assert render_nextflow_overlay(policy_state) != initial_bytes
    assert render_nextflow_overlay(sif_state) != initial_bytes


def test_batch_quoting_contains_shell_metacharacters_without_command_injection() -> None:
    argv = (
        "/opt/runtime/python3",
        "-I",
        "-S",
        "/opt/runtime/bioexec-compute-bootstrap",
        "--contract-version=1.0",
        "--config=/srv/config with 'quote;$(touch nope)/scheduler.json",
        "--run-id=run-1",
        f"--identity-sha256={'a' * 64}",
        f"--bootstrap-sha256={'b' * 64}",
    )

    script = render_workload_batch(argv)

    assert b"'\"'\"'" in script
    assert script.count(b"exec ") == 1
    assert (
        subprocess.run(
            ["/bin/sh", "-n"],
            input=script,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "python_flag",
        "version",
        "python_leaf",
        "bootstrap_leaf",
        "python_parent",
        "bootstrap_parent",
        "config_parent",
        "config_root",
        "control",
        "unicode",
        "zero",
    ],
)
def test_batch_renderer_rejects_every_open_surface(mutation: str) -> None:
    value = [
        "/opt/runtime/python3",
        "-I",
        "-S",
        "/opt/runtime/bioexec-compute-bootstrap",
        "--contract-version=1.0",
        "--config=/srv/config/scheduler.json",
        "--run-id=run-1",
        f"--identity-sha256={'a' * 64}",
        f"--bootstrap-sha256={'b' * 64}",
    ]
    if mutation == "missing":
        value.pop()
    elif mutation == "extra":
        value.append("--shell=/bin/sh")
    elif mutation == "python_flag":
        value[1] = "-c"
    elif mutation == "version":
        value[4] = "--contract-version=2.0"
    elif mutation == "python_leaf":
        value[0] = "/opt/runtime/python"
    elif mutation == "bootstrap_leaf":
        value[3] = "/opt/runtime/bioexec"
    elif mutation == "python_parent":
        value[0] = "/opt/runtime/../runtime/python3"
    elif mutation == "bootstrap_parent":
        value[3] = "/opt/runtime/../runtime/bioexec-compute-bootstrap"
    elif mutation == "config_parent":
        value[5] = "--config=/srv/config/../config/scheduler.json"
    elif mutation == "config_root":
        value[5] = "--config=/"
    elif mutation == "control":
        value[5] = "--config=/srv/config\n/scheduler.json"
    elif mutation == "unicode":
        value[5] = "--config=/srv/配置/scheduler.json"
    else:
        value[7] = f"--identity-sha256={'0' * 64}"

    with pytest.raises(SchedulerWorkloadError):
        render_workload_batch(tuple(value))


def test_prepare_contract_never_spawns_or_execs(
    workload: tuple[RunFixture, SchedulerStateSnapshot, SchedulerWorkloadPlan],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, preflight, plan = workload
    snapshot = fixture.run_store.load(plan.run_id)

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("pure workload construction attempted process execution")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "execve", forbidden)

    repeated = prepare_scheduler_workload(fixture.state.config, snapshot, preflight)
    assert repeated.binding_sha256 == plan.binding_sha256


def test_version_one_import_graph_does_not_load_workload_contract() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "import bioexec.main\n"
        "assert 'bioexec.scheduler_workload' not in sys.modules\n"
        "assert 'bioexec.scheduler_run' not in sys.modules\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
