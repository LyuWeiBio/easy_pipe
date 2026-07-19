"""Controller-side tests for the dormant M7 scheduler profile contract."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from bioexec.slurm import (
    SlurmContractError,
    SlurmSchedulerPolicy,
)
from bioexec.slurm import (
    canonical_scheduler_policy_bytes as remote_policy_bytes,
)
from bioexec.slurm import (
    scheduler_policy_hash as remote_policy_hash,
)
from biopipe.execution.models import ExecutionProfile
from biopipe.execution.scheduler_models import (
    SlurmExecutionProfileV2,
    SlurmSchedulerPolicyV2,
    canonical_scheduler_policy_bytes,
    scheduler_policy_hash,
)


def _scheduler(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "partition": "compute",
        "account": "bioinfo",
        "qos": "normal",
        "time_limit": "08:00:00",
        "cpus_per_task": 8,
        "memory_mib": 16_384,
        "submit_timeout_seconds": 60,
        "status_poll_seconds": 30,
        "max_pending_seconds": 3_600,
    }
    value.update(updates)
    return value


def _profile(**updates: object) -> SlurmExecutionProfileV2:
    value: dict[str, Any] = {
        "profile_id": "hpc01-slurm",
        "source_host": "hpc01",
        "execution_host": "hpc01",
        "ssh_alias": "hpc01-executor",
        "approval_signer": {
            "key_id": "controller-2026-01",
            "key_file": "/secure/controller-2026-01.key",
        },
        "allowed_roots": {
            "deploy": ["/srv/biopipe/deployments"],
            "work": ["/srv/biopipe/work"],
            "output": ["/srv/biopipe/results"],
            "cache": ["/srv/biopipe/cache"],
        },
        "scheduler": _scheduler(),
        "containers": {
            "fastqc": {
                "image": "quay.io/biocontainers/fastqc:0.12.1--hdfd78af_0",
                "digest": f"sha256:{'a' * 64}",
                "local_path": "/srv/biopipe/cache/fastqc.sif",
                "file_sha256": "b" * 64,
            }
        },
        "path_mapping": [{"source_prefix": "/data/raw", "execution_prefix": "/shared/raw"}],
    }
    value.update(updates)
    return SlurmExecutionProfileV2.model_validate(value)


def test_profile_v2_names_the_outer_and_inner_executors_unambiguously() -> None:
    profile = _profile()

    assert profile.profile_version == "2.0"
    assert profile.runtime.model_dump() == {
        "launch_backend": "slurm",
        "workflow_engine": "nextflow",
        "workflow_executor": "local",
        "container_engine": "apptainer",
        "topology": "single_allocation_nextflow_local",
    }
    assert profile.scheduler.cpus_per_task == 8
    assert profile.scheduler.memory_mib == 16_384
    assert len(profile.profile_hash()) == 64


def test_controller_and_remote_scheduler_policy_have_identical_bytes_and_hash() -> None:
    mapping = _scheduler()
    controller = SlurmSchedulerPolicyV2.model_validate(mapping)
    remote = SlurmSchedulerPolicy.from_mapping(mapping)

    assert controller.as_mapping() == remote.as_mapping()
    assert canonical_scheduler_policy_bytes(controller) == remote_policy_bytes(remote)
    assert scheduler_policy_hash(controller) == remote_policy_hash(remote)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("partition", "compute;id"),
        ("partition", " compute"),
        ("account", 123),
        ("time_limit", "24:00:00"),
        ("time_limit", "08:00:00 "),
        ("cpus_per_task", True),
        ("memory_mib", 1_023),
        ("submit_timeout_seconds", "60"),
        ("status_poll_seconds", 3_601),
        ("max_pending_seconds", 59),
        ("extra_flags", ["--exclusive"]),
    ],
)
def test_controller_and_remote_reject_the_same_policy_mutations(
    field: str,
    invalid: object,
) -> None:
    mapping = _scheduler(**{field: invalid})

    with pytest.raises(ValidationError):
        SlurmSchedulerPolicyV2.model_validate(mapping)
    with pytest.raises(SlurmContractError):
        SlurmSchedulerPolicy.from_mapping(mapping)


def test_controller_and_remote_require_the_same_complete_policy_field_set() -> None:
    for field in _scheduler():
        mapping = _scheduler()
        del mapping[field]
        with pytest.raises(ValidationError):
            SlurmSchedulerPolicyV2.model_validate(mapping)
        with pytest.raises(SlurmContractError):
            SlurmSchedulerPolicy.from_mapping(mapping)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("partition", "long"),
        ("account", None),
        ("qos", None),
        ("time_limit", "09:00:00"),
        ("cpus_per_task", 9),
        ("memory_mib", 16_385),
        ("submit_timeout_seconds", 61),
        ("status_poll_seconds", 31),
        ("max_pending_seconds", 3_601),
    ],
)
def test_every_scheduler_value_changes_profile_identity(field: str, replacement: object) -> None:
    original = _profile()
    changed = _profile(scheduler=_scheduler(**{field: replacement}))

    assert changed.profile_hash() != original.profile_hash()
    assert scheduler_policy_hash(changed.scheduler) != scheduler_policy_hash(original.scheduler)


@pytest.mark.parametrize(
    "updates",
    [
        {"extra_flags": ["--exclusive"]},
        {"command": "id"},
        {"script": "#!/bin/sh\nid"},
        {"environment": {"SBATCH_ACCOUNT": "other"}},
        {"cluster": "other"},
        {"cancel": True},
    ],
)
def test_scheduler_policy_rejects_unreviewed_surfaces(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SlurmSchedulerPolicyV2.model_validate({**_scheduler(), **updates})


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("partition", "-compute"),
        ("partition", "compute;id"),
        ("account", "bio info"),
        ("qos", "normal\n#SBATCH --wrap=id"),
        ("time_limit", "8:00:00"),
        ("time_limit", "24:00:00"),
        ("cpus_per_task", True),
        ("cpus_per_task", 1_025),
        ("memory_mib", 1_023),
        ("memory_mib", 16 * 1024 * 1024 + 1),
        ("submit_timeout_seconds", 0),
        ("status_poll_seconds", 3_601),
        ("max_pending_seconds", 59),
    ],
)
def test_scheduler_policy_rejects_injection_and_unbounded_resources(
    field: str,
    invalid: object,
) -> None:
    with pytest.raises(ValidationError):
        SlurmSchedulerPolicyV2.model_validate(_scheduler(**{field: invalid}))


@pytest.mark.parametrize(
    "runtime",
    [
        {"launch_backend": "local"},
        {"launch_backend": " slurm"},
        {"workflow_executor": "slurm"},
        {"container_engine": "docker"},
        {"topology": "task_per_job"},
        {"module": "slurm"},
    ],
)
def test_profile_rejects_every_other_topology(runtime: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _profile(runtime=runtime)


def test_profile_requires_hash_bound_sifs_below_the_shared_cache() -> None:
    missing_hash = _profile().model_dump(mode="json")
    missing_hash["containers"]["fastqc"]["file_sha256"] = None
    with pytest.raises(ValidationError, match="hashed local SIF"):
        SlurmExecutionProfileV2.model_validate(missing_hash)

    outside = _profile().model_dump(mode="json")
    outside["containers"]["fastqc"]["local_path"] = "/tmp/fastqc.sif"
    with pytest.raises(ValidationError, match="shared cache"):
        SlurmExecutionProfileV2.model_validate(outside)


def test_frozen_v1_profile_rejects_v2_and_scheduler_fields() -> None:
    value = _profile().model_dump(mode="json")

    with pytest.raises(ValidationError):
        ExecutionProfile.model_validate(value)


def test_profile_v2_runtime_schema_is_strict_without_joining_v1_catalog() -> None:
    schema = SlurmExecutionProfileV2.model_json_schema()

    assert schema["additionalProperties"] is False
    assert schema["properties"]["profile_version"]["const"] == "2.0"
    assert schema["properties"]["scheduler"]["$ref"].endswith("SlurmSchedulerPolicyV2")


def test_frozen_v1_catalog_identity_cannot_move_with_m7_contracts() -> None:
    payload = Path("src/biopipe/schema_v1/catalog.json").read_bytes()
    catalog = json.loads(payload)

    assert hashlib.sha256(payload).hexdigest() == (
        "427bb4168ffe684e8a77c268b77a06405b982902e42df691424f9356c442bfa4"
    )
    assert catalog["catalog_sha256"] == (
        "f2e25d057be6a9acc9e8007f8f0c46bea7f7b6af5d4da1657357d787a631524a"
    )


def test_v2_profile_has_no_current_controller_entrypoint() -> None:
    roots = (
        Path("src/biopipe/cli"),
        Path("src/biopipe/execution/profiles.py"),
        Path("src/biopipe/execution/preflight.py"),
        Path("src/biopipe/execution/gate.py"),
        Path("src/biopipe/execution/runner.py"),
        Path("src/biopipe/execution/client.py"),
        Path("src/biopipe/execution/signing.py"),
    )
    files = tuple(
        path for root in roots for path in (root.rglob("*.py") if root.is_dir() else (root,))
    )

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert "biopipe.execution.scheduler_models" not in imports, path
