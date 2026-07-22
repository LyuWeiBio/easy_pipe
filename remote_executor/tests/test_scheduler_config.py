"""Contract tests for dormant scheduler-aware Remote Executor config v2."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

import bioexec.scheduler_config as scheduler_config_module
from bioexec.scheduler_config import (
    SCHEDULER_CONFIG_VERSION,
    SCHEDULER_PROFILE_VERSION,
    SchedulerConfigError,
    SchedulerLimits,
    SchedulerRuntime,
    canonical_scheduler_policy_hash,
    parse_scheduler_config,
)
from bioexec.slurm import SlurmSchedulerPolicy


def _valid_config() -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "profile_version": "2.0",
        "profile_id": "hpc01-slurm",
        "profile_hash": "a" * 64,
        "runtime": {
            "launch_backend": "slurm",
            "workflow_engine": "nextflow",
            "workflow_executor": "local",
            "container_engine": "apptainer",
            "topology": "single_allocation_nextflow_local",
        },
        "scheduler": {
            "partition": "compute",
            "account": "bioinfo",
            "qos": "normal",
            "time_limit": "08:00:00",
            "cpus_per_task": 8,
            "memory_mib": 32_768,
            "submit_timeout_seconds": 60,
            "status_poll_seconds": 30,
            "max_pending_seconds": 3_600,
        },
        "read_roots": ["/data/raw"],
        "deploy_roots": ["/srv/biopipe/deployments"],
        "work_roots": ["/srv/biopipe/work"],
        "output_roots": ["/srv/biopipe/results"],
        "cache_roots": ["/srv/biopipe/container-cache"],
        "state_root": "/srv/biopipe/private-state",
        "executables": {
            "python": "/usr/bin/python3",
            "java": "/usr/bin/java",
            "nextflow": "/usr/local/bin/nextflow",
            "apptainer": "/usr/bin/apptainer",
            "compute_worker": "/opt/biopipe/bin/bioexec-compute-preflight",
            "compute_bootstrap": "/opt/biopipe/bin/bioexec-compute-bootstrap",
            "sbatch": "/opt/slurm/bin/sbatch",
            "squeue": "/opt/slurm/bin/squeue",
            "sacct": "/opt/slurm/bin/sacct",
            "scontrol": "/opt/slurm/bin/scontrol",
        },
        "nextflow_version": "24.10.0",
        "nextflow_jar": "/srv/biopipe/runtime/nextflow-24.10.0-one.jar",
        "nextflow_jar_sha256": "b" * 64,
        "approval_key_id": "controller-2026-01",
        "approval_hmac_key": "c" * 64,
        "limits": {},
    }


def test_exact_v2_config_parses_without_accessing_declared_paths() -> None:
    value = _valid_config()

    config = parse_scheduler_config(value)

    assert config.schema_version == SCHEDULER_CONFIG_VERSION == "2.0"
    assert config.profile_version == SCHEDULER_PROFILE_VERSION == "2.0"
    assert config.runtime.as_mapping() == value["runtime"]
    assert config.scheduler.as_mapping() == value["scheduler"]
    assert config.executables.as_mapping() == value["executables"]
    assert config.approval_hmac_key == bytes.fromhex("c" * 64)
    assert "cccccccc" not in repr(config)
    assert config.limits == SchedulerLimits()


@pytest.mark.parametrize("field", sorted(_valid_config()))
def test_top_level_fields_are_all_required(field: str) -> None:
    value = _valid_config()
    del value[field]

    with pytest.raises(SchedulerConfigError, match="configuration fields"):
        parse_scheduler_config(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "1.0"),
        ("profile_version", "1.0"),
        ("profile_id", "bad profile"),
        ("profile_hash", "A" * 64),
        ("profile_hash", "0" * 64),
        ("nextflow_version", "bad version"),
        ("nextflow_jar", "relative.jar"),
        ("nextflow_jar_sha256", "0" * 64),
        ("approval_key_id", "-bad"),
        ("approval_hmac_key", "0" * 64),
    ],
)
def test_versions_identifiers_digests_and_key_fail_closed(field: str, value: Any) -> None:
    config = _valid_config()
    config[field] = value

    with pytest.raises(SchedulerConfigError):
        parse_scheduler_config(config)


def test_top_level_extensions_are_rejected() -> None:
    value = _valid_config()
    value["extra_flags"] = ["--oversubscribe"]

    with pytest.raises(SchedulerConfigError, match="configuration fields"):
        parse_scheduler_config(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("launch_backend", "local"),
        ("workflow_engine", "snakemake"),
        ("workflow_executor", "slurm"),
        ("container_engine", "docker"),
        ("topology", "task_per_job"),
    ],
)
def test_runtime_is_one_slurm_allocation_with_nextflow_local_and_apptainer(
    field: str, value: str
) -> None:
    config = _valid_config()
    config["runtime"][field] = value

    with pytest.raises(SchedulerConfigError, match="runtime must select"):
        parse_scheduler_config(config)


def test_runtime_rejects_missing_and_extension_fields() -> None:
    missing = _valid_config()
    del missing["runtime"]["topology"]
    with pytest.raises(SchedulerConfigError, match="runtime fields"):
        parse_scheduler_config(missing)

    extension = _valid_config()
    extension["runtime"]["modules"] = ["slurm"]
    with pytest.raises(SchedulerConfigError, match="runtime fields"):
        parse_scheduler_config(extension)


@pytest.mark.parametrize("forbidden", ["docker", "scancel", "shell", "bash"])
def test_executable_contract_has_no_forbidden_command_surface(forbidden: str) -> None:
    config = _valid_config()
    config["executables"][forbidden] = f"/usr/bin/{forbidden}"

    with pytest.raises(SchedulerConfigError, match="executables fields"):
        parse_scheduler_config(config)


@pytest.mark.parametrize(
    "field",
    [
        "python",
        "java",
        "nextflow",
        "apptainer",
        "compute_worker",
        "compute_bootstrap",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    ],
)
def test_every_fixed_executable_is_required(field: str) -> None:
    config = _valid_config()
    del config["executables"][field]

    with pytest.raises(SchedulerConfigError, match="executables fields"):
        parse_scheduler_config(config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sbatch", "sbatch"),
        ("sbatch", "/opt/slurm/bin/squeue"),
        ("scontrol", "/opt/slurm/../bin/scontrol"),
        ("python", "/usr/bin/python"),
        ("compute_worker", "/opt/biopipe/bin/compute_worker"),
        ("compute_bootstrap", "/opt/biopipe/bin/compute_bootstrap"),
        ("java", "/"),
        ("nextflow", "/usr/local/bin/nextflow\n--help"),
    ],
)
def test_executable_paths_are_canonical_absolute_fixed_leafs(field: str, value: str) -> None:
    config = _valid_config()
    config["executables"][field] = value

    with pytest.raises(SchedulerConfigError):
        parse_scheduler_config(config)


def test_scheduler_policy_is_reused_and_rejects_free_flags() -> None:
    config = _valid_config()
    config["scheduler"]["extra_flags"] = ["--wrap=touch /tmp/escaped"]

    with pytest.raises(SchedulerConfigError, match="scheduler policy"):
        parse_scheduler_config(config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("partition", "compute;id"),
        ("account", "bio info"),
        ("qos", "normal\n--wrap=id"),
        ("time_limit", "8 hours"),
        ("cpus_per_task", True),
        ("cpus_per_task", 0),
        ("memory_mib", 1023),
        ("submit_timeout_seconds", 301),
        ("status_poll_seconds", 4),
        ("max_pending_seconds", 59),
    ],
)
def test_scheduler_policy_invalid_values_are_rejected(field: str, value: Any) -> None:
    config = _valid_config()
    config["scheduler"][field] = value

    with pytest.raises(SchedulerConfigError, match="scheduler policy"):
        parse_scheduler_config(config)


def test_optional_account_and_qos_must_remain_explicit() -> None:
    config = _valid_config()
    config["scheduler"]["account"] = None
    config["scheduler"]["qos"] = None
    parsed = parse_scheduler_config(config)
    assert parsed.scheduler.account is parsed.scheduler.qos is None

    del config["scheduler"]["account"]
    with pytest.raises(SchedulerConfigError, match="scheduler policy"):
        parse_scheduler_config(config)


def test_scheduler_policy_hash_is_canonical_order_independent_and_resource_bound() -> None:
    first_mapping = _valid_config()["scheduler"]
    second_mapping = dict(reversed(tuple(first_mapping.items())))
    first = SlurmSchedulerPolicy.from_mapping(first_mapping)
    second = SlurmSchedulerPolicy.from_mapping(second_mapping)

    first_hash = canonical_scheduler_policy_hash(first)

    assert first_hash == canonical_scheduler_policy_hash(second)
    assert (
        first_hash
        == hashlib.sha256(
            json.dumps(
                first.as_mapping(),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
    )
    changed_mapping = dict(first_mapping)
    changed_mapping["memory_mib"] += 1024
    assert first_hash != canonical_scheduler_policy_hash(
        SlurmSchedulerPolicy.from_mapping(changed_mapping)
    )


def test_scheduler_policy_hash_requires_a_validated_policy() -> None:
    with pytest.raises(SchedulerConfigError, match="validated"):
        canonical_scheduler_policy_hash(_valid_config()["scheduler"])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field,value",
    [
        ("read_roots", []),
        ("read_roots", ["relative"]),
        ("read_roots", ["/"]),
        ("read_roots", ["/data//raw"]),
        ("read_roots", ["/data/raw", "/data/raw"]),
        ("read_roots", ["/data", "/data/raw"]),
        ("state_root", "/srv/biopipe/../private-state"),
    ],
)
def test_roots_are_bounded_canonical_and_unambiguous(field: str, value: Any) -> None:
    config = _valid_config()
    config[field] = value

    with pytest.raises(SchedulerConfigError):
        parse_scheduler_config(config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("deploy_roots", ["/data/raw/jobs"]),
        ("work_roots", ["/srv/biopipe/deployments/work"]),
        ("output_roots", ["/srv/biopipe"]),
        ("cache_roots", ["/srv/biopipe/private-state/cache"]),
        ("state_root", "/srv/biopipe/results/state"),
    ],
)
def test_root_roles_must_not_overlap(field: str, value: Any) -> None:
    config = _valid_config()
    config[field] = value

    with pytest.raises(SchedulerConfigError, match="roles must not overlap"):
        parse_scheduler_config(config)


def test_roots_are_canonically_sorted() -> None:
    config = _valid_config()
    config["read_roots"] = ["/z/raw", "/a/raw"]

    parsed = parse_scheduler_config(config)

    assert parsed.read_roots == ("/a/raw", "/z/raw")


@pytest.mark.parametrize(
    "key,value",
    [
        ("max_request_bytes", True),
        ("max_response_bytes", 511),
        ("max_deployment_files", 0),
        ("max_file_bytes", 0),
        ("max_deployment_bytes", 0),
        ("max_raw_paths", 0),
        ("max_command_output_bytes", 1023),
        ("command_timeout_seconds", float("nan")),
        ("run_timeout_seconds", float("inf")),
        ("preflight_ttl_seconds", 0),
        ("minimum_free_bytes", 1024),
    ],
)
def test_limit_overrides_are_strict_and_finite(key: str, value: Any) -> None:
    config = _valid_config()
    config["limits"][key] = value

    with pytest.raises(SchedulerConfigError):
        parse_scheduler_config(config)


def test_limits_reject_extensions_and_incoherent_file_budget() -> None:
    extension = _valid_config()
    extension["limits"]["scheduler_output_bytes"] = 4096
    with pytest.raises(SchedulerConfigError, match="unsupported"):
        parse_scheduler_config(extension)

    incoherent = _valid_config()
    incoherent["limits"].update(
        {"max_file_bytes": 32 * 1024**2, "max_deployment_bytes": 16 * 1024**2}
    )
    with pytest.raises(SchedulerConfigError, match="must not exceed"):
        parse_scheduler_config(incoherent)


def test_parser_does_not_mutate_the_input_mapping() -> None:
    value = _valid_config()
    before = copy.deepcopy(value)

    parse_scheduler_config(value)

    assert value == before


def test_scheduler_config_module_is_pure_and_dormant() -> None:
    source = inspect.getsource(scheduler_config_module)
    tree = ast.parse(source)
    imported_roots = {
        alias.name.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        (node.module or "").split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0
    )
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert imported_roots <= {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "math",
        "pathlib",
        "re",
        "typing",
    }
    assert called_names.isdisjoint({"open", "exec", "eval", "compile", "__import__"})
    assert "subprocess" not in source


@pytest.mark.parametrize(
    "path",
    [
        Path("remote_executor/src/bioexec/main.py"),
        Path("remote_executor/src/bioexec/config.py"),
        Path("remote_executor/src/bioexec/protocol.py"),
        Path("remote_executor/src/bioexec/runner.py"),
    ],
)
def test_existing_entrypoints_do_not_import_scheduler_config(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert all(
        "scheduler_config" not in (node.module or "")
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert all(
        all("scheduler_config" not in alias.name for alias in node.names)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
    )


def test_direct_runtime_construction_cannot_broaden_the_topology() -> None:
    with pytest.raises(SchedulerConfigError, match="runtime must select"):
        SchedulerRuntime(
            launch_backend="slurm",
            workflow_engine="nextflow",
            workflow_executor="slurm",
            container_engine="apptainer",
            topology="single_allocation_nextflow_local",
        )
