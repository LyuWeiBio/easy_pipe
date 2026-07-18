from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from bioexec.config import (
    AgentConfig,
    ConfiguredRoot,
    ExecutableIdentity,
    Executables,
    Limits,
)


def _root(path: Path) -> ConfiguredRoot:
    metadata = path.stat()
    return ConfiguredRoot(path=path, device=metadata.st_dev, inode=metadata.st_ino)


def _script(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def _executable_identity(path: Path) -> ExecutableIdentity:
    metadata = path.stat()
    return ExecutableIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


@pytest.fixture
def agent_config(tmp_path: Path) -> AgentConfig:
    roots = {}
    for name in ("read", "deploy", "work", "output", "cache", "state"):
        path = tmp_path / name
        path.mkdir(mode=0o700)
        roots[name] = _root(path)
    binary = tmp_path / "bin"
    binary.mkdir(mode=0o700)
    java = _script(binary / "java", "#!/bin/sh\necho java 21 >&2\n")
    nextflow = _script(
        binary / "nextflow",
        "#!/bin/sh\n"
        'if [ "${1:-}" = "-version" ]; then echo \'nextflow 24.10.0\'; exit 0; fi\n'
        'echo "$@"\n'
        'exit "${BIOEXEC_TEST_EXIT_CODE:-0}"\n',
    )
    docker = _script(binary / "docker", '#!/bin/sh\necho "$@"\n')
    apptainer = _script(binary / "apptainer", '#!/bin/sh\necho "$@"\n')
    nextflow_jar = binary / "nextflow-24.10.0-one.jar"
    nextflow_jar.write_bytes(b"synthetic pinned nextflow jar\n")
    nextflow_jar.chmod(0o444)
    return AgentConfig(
        profile_id="profile-1",
        profile_hash="a" * 64,
        read_roots=(roots["read"],),
        deploy_roots=(roots["deploy"],),
        work_roots=(roots["work"],),
        output_roots=(roots["output"],),
        cache_roots=(roots["cache"],),
        state_root=roots["state"],
        executables=Executables(
            java=java,
            nextflow=nextflow,
            apptainer=apptainer,
            docker=docker,
            java_identity=_executable_identity(java),
            nextflow_identity=_executable_identity(nextflow),
            apptainer_identity=_executable_identity(apptainer),
            docker_identity=_executable_identity(docker),
        ),
        nextflow_version="24.10.0",
        nextflow_jar=nextflow_jar,
        nextflow_jar_sha256=hashlib.sha256(nextflow_jar.read_bytes()).hexdigest(),
        nextflow_jar_identity=_executable_identity(nextflow_jar),
        approval_key_id="controller-test-key",
        approval_hmac_key=bytes.fromhex("d" * 64),
        limits=Limits(
            max_request_bytes=4 * 1024 * 1024,
            max_response_bytes=1024 * 1024,
            max_deployment_files=32,
            max_file_bytes=1024 * 1024,
            max_deployment_bytes=4 * 1024 * 1024,
            max_raw_paths=100,
            max_command_output_bytes=64 * 1024,
            command_timeout_seconds=3,
            run_timeout_seconds=10,
            preflight_ttl_seconds=300,
            minimum_free_bytes=1,
        ),
    )


def core_hashes(config: AgentConfig) -> dict[str, str]:
    return {
        "dataset_manifest": "1" * 64,
        "pipeline_spec": "2" * 64,
        "execution_plan": "3" * 64,
        "software_lock": "4" * 64,
        "execution_profile": config.profile_hash,
    }


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def project_hash(config: AgentConfig) -> str:
    hashes = core_hashes(config)
    return canonical_hash(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        }
    )


@pytest.fixture
def make_preflight_payload(
    agent_config: AgentConfig,
) -> Callable[..., dict[str, Any]]:
    raw = agent_config.read_roots[0].path / "sample_R1.fastq.gz"
    raw.write_bytes(b"synthetic-not-real-data\n")
    cache = agent_config.cache_roots[0].path / "job-cache"
    cache.mkdir()

    def make(**updates: Any) -> dict[str, Any]:
        digest = "b" * 64
        value: dict[str, Any] = {
            "preflight_id": "preflight-1",
            "profile_id": agent_config.profile_id,
            "profile_hash": agent_config.profile_hash,
            "project_hash": project_hash(agent_config),
            "artifact_hashes": core_hashes(agent_config),
            "source_host": "host-1",
            "execution_host": "host-1",
            "host_relation": "same",
            "source_paths": [str(raw)],
            "execution_paths": [str(raw)],
            "path_mapping": [],
            "deploy_dir": str(agent_config.deploy_roots[0].path / "deployment-1"),
            "work_dir": str(agent_config.work_roots[0].path / "work-1"),
            "output_dir": str(agent_config.output_roots[0].path / "results-1"),
            "cache_dir": str(cache),
            "container_engine": "docker",
            "containers": [
                {
                    "name": "fastqc",
                    "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
                    "digest": f"sha256:{digest}",
                    "local_path": None,
                    "file_sha256": None,
                },
                {
                    "name": "multiqc",
                    "image": "quay.io/biocontainers/multiqc:1.27.1--pyhdfd78af_0",
                    "digest": f"sha256:{'c' * 64}",
                    "local_path": None,
                    "file_sha256": None,
                },
            ],
            "minimum_free_bytes": 1,
            "network_disabled": True,
        }
        value.update(updates)
        return value

    return make


def deployment_contents() -> dict[str, bytes]:
    names = {
        "assets/samplesheet.csv",
        "conf/base.config",
        "conf/local.config",
        "dataset.manifest.resolved.json",
        "execution.plan.yaml",
        "main.nf",
        "modules/fastqc/raw.nf",
        "modules/multiqc/main.nf",
        "nextflow.config",
        "pipeline.spec.yaml",
        "software.lock.yaml",
    }
    return {name: f"synthetic fixture: {name}\n".encode() for name in names}


def bundle_hash(contents: dict[str, bytes]) -> str:
    metadata = [
        {
            "path": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        for name, content in sorted(contents.items())
    ]
    return canonical_hash(metadata)


def deployment_files(contents: dict[str, bytes]) -> list[dict[str, Any]]:
    import base64

    return [
        {
            "path": name,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_base64": base64.b64encode(content).decode("ascii"),
        }
        for name, content in sorted(contents.items())
    ]


def config_json(config: AgentConfig) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "profile_id": config.profile_id,
        "profile_hash": config.profile_hash,
        "read_roots": [str(value.path) for value in config.read_roots],
        "deploy_roots": [str(value.path) for value in config.deploy_roots],
        "work_roots": [str(value.path) for value in config.work_roots],
        "output_roots": [str(value.path) for value in config.output_roots],
        "cache_roots": [str(value.path) for value in config.cache_roots],
        "state_root": str(config.state_root.path),
        "executables": {
            "java": str(config.executables.java),
            "nextflow": str(config.executables.nextflow),
            "apptainer": str(config.executables.apptainer),
            "docker": str(config.executables.docker),
        },
        "nextflow_version": config.nextflow_version,
        "nextflow_jar": str(config.nextflow_jar),
        "nextflow_jar_sha256": config.nextflow_jar_sha256,
        "approval_key_id": config.approval_key_id,
        "approval_hmac_key": config.approval_hmac_key.hex(),
        "limits": {
            "max_request_bytes": config.limits.max_request_bytes,
            "max_response_bytes": config.limits.max_response_bytes,
            "max_deployment_files": config.limits.max_deployment_files,
            "max_file_bytes": config.limits.max_file_bytes,
            "max_deployment_bytes": config.limits.max_deployment_bytes,
            "max_raw_paths": config.limits.max_raw_paths,
            "max_command_output_bytes": config.limits.max_command_output_bytes,
            "command_timeout_seconds": config.limits.command_timeout_seconds,
            "run_timeout_seconds": config.limits.run_timeout_seconds,
            "preflight_ttl_seconds": config.limits.preflight_ttl_seconds,
            "minimum_free_bytes": 1024 * 1024,
        },
    }


def write_config(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, json.dumps(value).encode("utf-8"))
    finally:
        os.close(descriptor)
