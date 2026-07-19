from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from bioexec.commands import CommandResult
from bioexec.config import AgentConfig
from bioexec.errors import AgentFailure
from bioexec.preflight import recheck_container_artifacts, run_preflight
from bioexec.state import StateStore


def test_preflight_passes_exact_nine_sorted_checks_and_mints_token(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    result, record = run_preflight(
        make_preflight_payload(),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert set(result) == {
        "preflight_id",
        "preflight_token",
        "status",
        "checks",
        "input_count",
        "input_set_hash",
    }
    assert result["status"] == "passed"
    assert isinstance(result["preflight_token"], str)
    names = [check["name"] for check in result["checks"]]
    assert names == sorted(names)
    assert names == [
        "cache_writable",
        "container",
        "disk_space",
        "host_relationship",
        "output_dir_writable",
        "path_mapping",
        "rawdata_readable",
        "runtime",
        "workdir_writable",
    ]
    assert record is not None
    assert "sample_R1.fastq.gz" in record["input_records"][0]["path"]
    assert record["input_records"][0]["path"] not in str(result["checks"])


def test_preflight_ordinary_failure_returns_report_without_token(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    missing = agent_config.read_roots[0].path / "missing.fastq.gz"
    payload = make_preflight_payload(
        source_paths=[str(missing)],
        execution_paths=[str(missing)],
    )
    result, record = run_preflight(payload, agent_config, state=StateStore(agent_config.state_root))
    assert result["status"] == "failed"
    assert result["preflight_token"] is None
    assert record is None
    checks = {check["name"]: check for check in result["checks"]}
    assert checks["rawdata_readable"]["status"] == "failed"


def test_preflight_reports_insufficient_disk_space_with_stable_check_code(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    result, record = run_preflight(
        make_preflight_payload(minimum_free_bytes=2**63 - 1),
        agent_config,
        state=StateStore(agent_config.state_root),
    )

    assert result["status"] == "failed"
    assert result["preflight_token"] is None
    assert record is None
    checks = {check["name"]: check for check in result["checks"]}
    assert checks["disk_space"]["name"] == "disk_space"
    assert checks["disk_space"]["status"] == "failed"
    assert checks["disk_space"]["code"] == "INSUFFICIENT_SPACE"
    assert [name for name, check in checks.items() if check["status"] == "failed"] == ["disk_space"]


def test_preflight_rejects_unknown_fields_and_project_hash_mismatch(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    with pytest.raises(AgentFailure) as unknown:
        run_preflight(
            make_preflight_payload(command="id"),
            agent_config,
            state=StateStore(agent_config.state_root),
        )
    assert unknown.value.code == "SCHEMA_ERROR"
    with pytest.raises(AgentFailure) as mismatch:
        run_preflight(
            make_preflight_payload(project_hash="f" * 64),
            agent_config,
            state=StateStore(agent_config.state_root),
        )
    assert mismatch.value.code == "PROFILE_BINDING_MISMATCH"


def test_preflight_rejects_nested_deployment_target(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    parent = agent_config.deploy_roots[0].path / "parent"
    parent.mkdir()
    with pytest.raises(AgentFailure) as raised:
        run_preflight(
            make_preflight_payload(deploy_dir=str(parent / "nested")),
            agent_config,
            state=StateStore(agent_config.state_root),
        )
    assert raised.value.code == "SCHEMA_ERROR"


def test_preflight_mapping_and_host_failures_are_sanitized(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    source = "/source/sample.fastq.gz"
    execution = str(agent_config.read_roots[0].path / "sample_R1.fastq.gz")
    result, record = run_preflight(
        make_preflight_payload(
            source_host="source-host",
            execution_host="execution-host",
            host_relation="shared",
            source_paths=[source],
            execution_paths=[execution],
            path_mapping=[],
        ),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert record is None
    checks = {check["name"]: check for check in result["checks"]}
    assert checks["host_relationship"]["status"] == "passed"
    assert checks["path_mapping"]["status"] == "failed"
    assert source not in str(result)


def test_apptainer_requires_and_hashes_local_image(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    image = agent_config.cache_roots[0].path / "job-cache" / "fastqc.sif"
    image.write_bytes(b"synthetic-container\n")
    import hashlib

    second_image = agent_config.cache_roots[0].path / "job-cache" / "multiqc.sif"
    second_image.write_bytes(b"synthetic-multiqc-container\n")
    containers = [
        {
            "name": "fastqc",
            "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
            "digest": f"sha256:{'b' * 64}",
            "local_path": str(image),
            "file_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        },
        {
            "name": "multiqc",
            "image": "quay.io/biocontainers/multiqc:1.27.1--pyhdfd78af_0",
            "digest": f"sha256:{'c' * 64}",
            "local_path": str(second_image),
            "file_sha256": hashlib.sha256(second_image.read_bytes()).hexdigest(),
        },
    ]
    result, record = run_preflight(
        make_preflight_payload(container_engine="apptainer", containers=containers),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert result["status"] == "passed"
    assert record is not None
    assert all("_local_fingerprint" in item for item in record["containers"])
    recheck_container_artifacts(record, agent_config)
    image.write_bytes(b"tampered image\n")
    with pytest.raises(AgentFailure) as changed:
        recheck_container_artifacts(record, agent_config)
    assert changed.value.code == "IMAGE_CHANGED_AFTER_PREFLIGHT"
    image.write_bytes(b"synthetic-container\n")
    containers[0]["file_sha256"] = "0" * 64
    failed, failed_record = run_preflight(
        make_preflight_payload(
            preflight_id="preflight-2",
            deploy_dir=str(agent_config.deploy_roots[0].path / "deployment-2"),
            work_dir=str(agent_config.work_roots[0].path / "work-2"),
            output_dir=str(agent_config.output_roots[0].path / "results-2"),
            container_engine="apptainer",
            containers=containers,
        ),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert failed_record is None
    assert {item["name"]: item for item in failed["checks"]}["container"]["code"] == (
        "IMAGE_DIGEST_MISMATCH"
    )

    containers[0]["file_sha256"] = hashlib.sha256(image.read_bytes()).hexdigest()
    image.unlink()
    missing, missing_record = run_preflight(
        make_preflight_payload(
            preflight_id="preflight-3",
            deploy_dir=str(agent_config.deploy_roots[0].path / "deployment-3"),
            work_dir=str(agent_config.work_roots[0].path / "work-3"),
            output_dir=str(agent_config.output_roots[0].path / "results-3"),
            container_engine="apptainer",
            containers=containers,
        ),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert missing["status"] == "failed"
    assert missing["preflight_token"] is None
    assert missing_record is None
    assert {item["name"]: item for item in missing["checks"]}["container"]["code"] == (
        "PATH_UNAVAILABLE"
    )


def test_docker_missing_locked_image_reports_stable_container_code(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    class MissingImageRunner:
        def run(
            self,
            argv: Any,
            *,
            cwd: Path,
            env: Any,
            timeout_seconds: float,
            output_limit_bytes: int,
        ) -> CommandResult:
            del cwd, env, timeout_seconds, output_limit_bytes
            arguments = tuple(argv)
            if (
                arguments[0] == str(agent_config.executables.docker)
                and "image" in arguments[1:]
                and "inspect" in arguments[1:]
            ):
                return CommandResult(arguments, 1, "", "")
            stdout = (
                f"nextflow {agent_config.nextflow_version}"
                if arguments[0] == str(agent_config.executables.nextflow)
                else "runtime available"
            )
            return CommandResult(arguments, 0, stdout, "")

    result, record = run_preflight(
        make_preflight_payload(),
        agent_config,
        command_runner=MissingImageRunner(),
        state=StateStore(agent_config.state_root),
    )

    assert result["status"] == "failed"
    assert result["preflight_token"] is None
    assert record is None
    checks = {item["name"]: item for item in result["checks"]}
    assert checks["runtime"]["status"] == "passed"
    assert checks["container"]["name"] == "container"
    assert checks["container"]["status"] == "failed"
    assert checks["container"]["code"] == "IMAGE_UNAVAILABLE"


def test_raw_input_group_writable_file_or_parent_fails_closed(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    raw = agent_config.read_roots[0].path / "sample_R1.fastq.gz"
    for index, mode in enumerate((0o664, 0o646), start=1):
        raw.chmod(mode)
        failed_file, record = run_preflight(
            make_preflight_payload(
                preflight_id=f"preflight-{index}",
                deploy_dir=str(agent_config.deploy_roots[0].path / f"deployment-{index}"),
                work_dir=str(agent_config.work_roots[0].path / f"work-{index}"),
                output_dir=str(agent_config.output_roots[0].path / f"results-{index}"),
            ),
            agent_config,
            state=StateStore(agent_config.state_root),
        )
        assert failed_file["status"] == "failed"
        assert record is None
        file_check = {item["name"]: item for item in failed_file["checks"]}["rawdata_readable"]
        assert file_check["status"] == "failed"
        assert file_check["code"] == "UNTRUSTED_PATH_PERMISSIONS"

    raw.chmod(0o644)
    parent = agent_config.read_roots[0].path / "incoming"
    parent.mkdir(mode=0o700)
    nested = parent / "nested.fastq.gz"
    nested.write_bytes(b"synthetic\n")
    parent.chmod(0o770)
    failed_parent, parent_record = run_preflight(
        make_preflight_payload(
            preflight_id="preflight-3",
            deploy_dir=str(agent_config.deploy_roots[0].path / "deployment-3"),
            work_dir=str(agent_config.work_roots[0].path / "work-3"),
            output_dir=str(agent_config.output_roots[0].path / "results-3"),
            source_paths=[str(nested)],
            execution_paths=[str(nested)],
        ),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert parent_record is None
    parent_check = {item["name"]: item for item in failed_parent["checks"]}["rawdata_readable"]
    assert parent_check["status"] == "failed"
    assert parent_check["code"] == "UNTRUSTED_PATH_PERMISSIONS"


def test_apptainer_group_writable_cache_chain_fails_closed(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    import hashlib

    cache = agent_config.cache_roots[0].path / "job-cache"
    fastqc = cache / "fastqc.sif"
    multiqc = cache / "multiqc.sif"
    fastqc.write_bytes(b"fastqc image\n")
    multiqc.write_bytes(b"multiqc image\n")
    cache.chmod(0o770)
    containers = [
        {
            "name": "fastqc",
            "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
            "digest": f"sha256:{'b' * 64}",
            "local_path": str(fastqc),
            "file_sha256": hashlib.sha256(fastqc.read_bytes()).hexdigest(),
        },
        {
            "name": "multiqc",
            "image": "quay.io/biocontainers/multiqc:1.27.1--pyhdfd78af_0",
            "digest": f"sha256:{'c' * 64}",
            "local_path": str(multiqc),
            "file_sha256": hashlib.sha256(multiqc.read_bytes()).hexdigest(),
        },
    ]
    failed, record = run_preflight(
        make_preflight_payload(container_engine="apptainer", containers=containers),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert record is None
    assert {item["name"]: item for item in failed["checks"]}["container"]["status"] == "failed"

    cache.chmod(0o700)
    fastqc.chmod(0o664)
    failed_file, file_record = run_preflight(
        make_preflight_payload(
            preflight_id="preflight-2",
            deploy_dir=str(agent_config.deploy_roots[0].path / "deployment-2"),
            work_dir=str(agent_config.work_roots[0].path / "work-2"),
            output_dir=str(agent_config.output_roots[0].path / "results-2"),
            container_engine="apptainer",
            containers=containers,
        ),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert file_record is None
    assert {item["name"]: item for item in failed_file["checks"]}["container"]["status"] == "failed"


def test_pinned_nextflow_jar_and_version_are_rechecked(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    jar = agent_config.nextflow_jar
    jar.chmod(0o644)
    jar.write_bytes(b"replaced jar\n")
    failed_jar, record = run_preflight(
        make_preflight_payload(),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert record is None
    assert {item["name"]: item for item in failed_jar["checks"]}["runtime"]["status"] == "failed"


def test_preflight_rejects_unpinned_nextflow_version(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    agent_config.executables.nextflow.write_text(
        "#!/bin/sh\necho 'nextflow 99.99.99'\n",
        encoding="utf-8",
    )
    agent_config.executables.nextflow.chmod(0o755)
    failed, record = run_preflight(
        make_preflight_payload(),
        agent_config,
        state=StateStore(agent_config.state_root),
    )
    assert record is None
    checks = {item["name"]: item for item in failed["checks"]}
    assert checks["runtime"]["code"] == "NEXTFLOW_VERSION_MISMATCH"


def test_preflight_runtime_receives_only_private_client_environment(
    agent_config: AgentConfig,
    make_preflight_payload: Any,
) -> None:
    environments: list[dict[str, str]] = []

    class CaptureRunner:
        def run(
            self,
            argv: Any,
            *,
            cwd: Path,
            env: Any,
            timeout_seconds: float,
            output_limit_bytes: int,
        ) -> CommandResult:
            del cwd, timeout_seconds, output_limit_bytes
            environments.append(dict(env))
            return CommandResult(
                tuple(argv),
                0,
                f"nextflow {agent_config.nextflow_version} sha256:{'b' * 64} sha256:{'c' * 64}",
                "",
            )

    result, record = run_preflight(
        make_preflight_payload(),
        agent_config,
        command_runner=CaptureRunner(),
        state=StateStore(agent_config.state_root),
    )
    assert result["status"] == "passed" and record is not None
    assert environments
    for environment in environments:
        assert environment["HOME"].startswith(str(agent_config.state_root.path))
        assert environment["NXF_HOME"].startswith(str(agent_config.state_root.path))
        assert environment["TMPDIR"].startswith(str(agent_config.state_root.path))
        assert environment["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        assert environment["NXF_BIN"] == str(agent_config.nextflow_jar)
        assert environment["JAVA_CMD"] == str(agent_config.executables.java)
        assert "HTTP_PROXY" not in environment
        assert os.environ.get("HOME") != environment["HOME"]
