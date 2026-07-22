"""Filesystem and reachability tests for the dormant trusted config-v2 loader."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import stat
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bioexec.scheduler_config_loader as loader_module
from bioexec.scheduler_config import SchedulerConfigError, parse_scheduler_config
from bioexec.scheduler_config_loader import (
    MAX_EXECUTABLE_BYTES,
    MAX_NEXTFLOW_JAR_BYTES,
    SchedulerConfigLoadError,
    TrustedDirectoryBinding,
    load_trusted_scheduler_config,
    verify_scheduler_config_file,
    verify_scheduler_executable,
    verify_scheduler_nextflow_jar,
    verify_scheduler_root,
)


@dataclass(frozen=True)
class SchedulerConfigFixture:
    config_path: Path
    value: dict[str, Any]
    roots: dict[str, Path]
    executables: dict[str, Path]
    nextflow_jar: Path


def _write_executable(path: Path, role: str) -> None:
    path.write_bytes(f"#!/bin/sh\necho {role}\n".encode("ascii"))
    path.chmod(0o755)


def _write_config(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o600)


@pytest.fixture
def scheduler_config_fixture(tmp_path: Path) -> SchedulerConfigFixture:
    roots: dict[str, Path] = {}
    for role in ("read", "deploy", "work", "output", "cache", "state"):
        root = tmp_path / role
        root.mkdir(mode=0o700)
        roots[role] = root

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o700)
    executable_roles = (
        "python",
        "java",
        "nextflow",
        "apptainer",
        "compute_worker",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    )
    executable_leaves = {
        role: (
            "python3"
            if role == "python"
            else "bioexec-compute-preflight"
            if role == "compute_worker"
            else role
        )
        for role in executable_roles
    }
    executables = {role: bin_dir / executable_leaves[role] for role in executable_roles}
    for role, path in executables.items():
        _write_executable(path, role)

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    nextflow_jar = runtime_dir / "nextflow-24.10.0-one.jar"
    nextflow_jar.write_bytes(b"synthetic trusted Nextflow JAR\n")
    nextflow_jar.chmod(0o444)

    value: dict[str, Any] = {
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
        "read_roots": [str(roots["read"])],
        "deploy_roots": [str(roots["deploy"])],
        "work_roots": [str(roots["work"])],
        "output_roots": [str(roots["output"])],
        "cache_roots": [str(roots["cache"])],
        "state_root": str(roots["state"]),
        "executables": {role: str(path) for role, path in executables.items()},
        "nextflow_version": "24.10.0",
        "nextflow_jar": str(nextflow_jar),
        "nextflow_jar_sha256": hashlib.sha256(nextflow_jar.read_bytes()).hexdigest(),
        "approval_key_id": "controller-2026-01",
        "approval_hmac_key": "c" * 64,
        "limits": {},
    }
    config_path = tmp_path / "scheduler-config.json"
    _write_config(config_path, value)
    return SchedulerConfigFixture(
        config_path=config_path,
        value=value,
        roots=roots,
        executables=executables,
        nextflow_jar=nextflow_jar,
    )


def test_trusted_loader_binds_exact_config_roots_executables_and_jar(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    fixture = scheduler_config_fixture

    loaded = load_trusted_scheduler_config(fixture.config_path)

    assert loaded.contract.schema_version == "2.0"
    assert loaded.contract.profile_version == "2.0"
    assert loaded.config_sha256 == hashlib.sha256(fixture.config_path.read_bytes()).hexdigest()
    assert (
        loaded.scheduler_policy_hash
        == hashlib.sha256(
            json.dumps(
                fixture.value["scheduler"],
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
    )
    assert loaded.read_roots[0].path == fixture.roots["read"]
    assert loaded.state_root.mode == 0o700
    assert tuple(loaded.executables) == (
        "python",
        "java",
        "nextflow",
        "apptainer",
        "compute_worker",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    )
    assert loaded.nextflow_jar.sha256 == fixture.value["nextflow_jar_sha256"]
    assert all(binding.sha256 is not None for binding in loaded.executables.values())
    assert "cccccccc" not in repr(loaded)
    with pytest.raises(TypeError):
        loaded.executables["shell"] = loaded.executables["java"]  # type: ignore[index]

    verify_scheduler_config_file(loaded)
    for role, roots in (
        ("read", loaded.read_roots),
        ("deploy", loaded.deploy_roots),
        ("work", loaded.work_roots),
        ("output", loaded.output_roots),
        ("cache", loaded.cache_roots),
    ):
        for index in range(len(roots)):
            verify_scheduler_root(loaded, role, index)  # type: ignore[arg-type]
    verify_scheduler_root(loaded, "state")
    for role in loaded.executables:
        verify_scheduler_executable(loaded, role)  # type: ignore[arg-type]
    verify_scheduler_nextflow_jar(loaded)


def test_loader_requires_explicit_canonical_absolute_config_path(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    with pytest.raises(SchedulerConfigLoadError, match="explicit and absolute"):
        load_trusted_scheduler_config(Path("scheduler-config.json"))

    double_anchor = Path("//") / str(scheduler_config_fixture.config_path).lstrip("/")
    assert str(double_anchor).startswith("//")
    with pytest.raises(SchedulerConfigLoadError, match="unsafe text"):
        load_trusted_scheduler_config(double_anchor)


def test_loader_ignores_environment_and_has_no_config_discovery(
    scheduler_config_fixture: SchedulerConfigFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BIOEXEC_CONFIG", "/must/not/be/read")
    monkeypatch.setenv("BIOEXEC_SCHEDULER_CONFIG", "/must/not/be/read")

    loaded = load_trusted_scheduler_config(scheduler_config_fixture.config_path)

    assert loaded.contract.profile_id == "hpc01-slurm"


def test_config_leaf_and_intermediate_symlinks_are_rejected(
    scheduler_config_fixture: SchedulerConfigFixture,
    tmp_path: Path,
) -> None:
    fixture = scheduler_config_fixture
    leaf_link = tmp_path / "config-link.json"
    leaf_link.symlink_to(fixture.config_path)
    with pytest.raises(SchedulerConfigLoadError, match="opened safely"):
        load_trusted_scheduler_config(leaf_link)

    real_parent = tmp_path / "real-config-parent"
    real_parent.mkdir(mode=0o700)
    nested = real_parent / "config.json"
    _write_config(nested, fixture.value)
    parent_link = tmp_path / "config-parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(SchedulerConfigLoadError, match="opened safely"):
        load_trusted_scheduler_config(parent_link / "config.json")


def test_config_mode_parent_permissions_and_size_fail_closed(
    scheduler_config_fixture: SchedulerConfigFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = scheduler_config_fixture
    fixture.config_path.chmod(0o640)
    with pytest.raises(SchedulerConfigLoadError, match="private file"):
        load_trusted_scheduler_config(fixture.config_path)

    fixture.config_path.chmod(0o600)
    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_config = unsafe_parent / "config.json"
    _write_config(unsafe_config, fixture.value)
    unsafe_parent.chmod(0o777)
    try:
        with pytest.raises(SchedulerConfigLoadError, match="opened safely"):
            load_trusted_scheduler_config(unsafe_config)
    finally:
        unsafe_parent.chmod(0o700)

    monkeypatch.setattr(loader_module, "MAX_SCHEDULER_CONFIG_BYTES", 32)
    with pytest.raises(SchedulerConfigLoadError, match=r"private file|byte budget"):
        load_trusted_scheduler_config(fixture.config_path)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":"2.0","schema_version":"2.0"}',
        b'{"value":NaN}',
        b"\xff",
        b"[]",
    ],
)
def test_config_requires_strict_duplicate_free_utf8_json(
    scheduler_config_fixture: SchedulerConfigFixture,
    payload: bytes,
) -> None:
    path = scheduler_config_fixture.config_path
    path.write_bytes(payload)
    path.chmod(0o600)

    with pytest.raises(SchedulerConfigLoadError):
        load_trusted_scheduler_config(path)


def test_surrogate_path_is_normalized_to_contract_and_loader_errors(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    value = scheduler_config_fixture.value
    value["nextflow_jar"] = "/srv/runtime/\ud800.jar"

    with pytest.raises(SchedulerConfigError, match="canonical absolute path"):
        parse_scheduler_config(value)

    _write_config(scheduler_config_fixture.config_path, value)
    with pytest.raises(SchedulerConfigLoadError, match="violates config-v2"):
        load_trusted_scheduler_config(scheduler_config_fixture.config_path)


def test_role_roots_require_no_follow_safe_modes_and_private_state(
    scheduler_config_fixture: SchedulerConfigFixture,
    tmp_path: Path,
) -> None:
    fixture = scheduler_config_fixture
    fixture.roots["work"].chmod(0o770)
    with pytest.raises(SchedulerConfigLoadError, match="root is unsafe"):
        load_trusted_scheduler_config(fixture.config_path)

    fixture.roots["work"].chmod(0o700)
    fixture.roots["state"].chmod(0o750)
    with pytest.raises(SchedulerConfigLoadError, match="root is unsafe"):
        load_trusted_scheduler_config(fixture.config_path)

    fixture.roots["state"].chmod(0o700)
    alias = tmp_path / "root-parent-link"
    alias.symlink_to(tmp_path, target_is_directory=True)
    fixture.value["read_roots"] = [str(alias / "read")]
    _write_config(fixture.config_path, fixture.value)
    with pytest.raises(SchedulerConfigLoadError, match="root is unsafe"):
        load_trusted_scheduler_config(fixture.config_path)


def test_read_root_may_have_data_owner_but_writable_root_may_not() -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o750,
        st_uid=os.geteuid() + 100_000,
    )

    loader_module._require_role_root(metadata, trusted_owner=False, private=False)
    with pytest.raises(OSError, match="unsafe ownership"):
        loader_module._require_role_root(metadata, trusted_owner=True, private=False)


def test_duplicate_filesystem_root_identities_are_rejected(
    scheduler_config_fixture: SchedulerConfigFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = loader_module._directory_identity

    def duplicate_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        _device, _inode, owner, group, mode = original(metadata)
        return 1, 1, owner, group, mode

    monkeypatch.setattr(loader_module, "_directory_identity", duplicate_identity)
    with pytest.raises(SchedulerConfigLoadError, match="roots alias"):
        load_trusted_scheduler_config(scheduler_config_fixture.config_path)


@pytest.mark.parametrize("failure", ["writable", "not-executable", "symlink"])
def test_executables_require_trusted_regular_executable_files(
    scheduler_config_fixture: SchedulerConfigFixture,
    failure: str,
) -> None:
    executable = scheduler_config_fixture.executables["sbatch"]
    if failure == "writable":
        executable.chmod(0o777)
    elif failure == "not-executable":
        executable.chmod(0o644)
    else:
        target = executable.with_name("sbatch-real")
        executable.rename(target)
        executable.symlink_to(target)

    with pytest.raises(SchedulerConfigLoadError, match=r"executable|opened safely"):
        load_trusted_scheduler_config(scheduler_config_fixture.config_path)


def test_hardlinked_executable_roles_are_rejected(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    fixture = scheduler_config_fixture
    fixture.executables["squeue"].unlink()
    os.link(fixture.executables["sbatch"], fixture.executables["squeue"])

    with pytest.raises(SchedulerConfigLoadError, match="executable roles alias"):
        load_trusted_scheduler_config(fixture.config_path)


def test_nextflow_jar_requires_exact_bounded_hash(
    scheduler_config_fixture: SchedulerConfigFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = scheduler_config_fixture
    fixture.value["nextflow_jar_sha256"] = "d" * 64
    _write_config(fixture.config_path, fixture.value)
    with pytest.raises(SchedulerConfigLoadError, match="does not match"):
        load_trusted_scheduler_config(fixture.config_path)

    fixture.value["nextflow_jar_sha256"] = hashlib.sha256(
        fixture.nextflow_jar.read_bytes()
    ).hexdigest()
    _write_config(fixture.config_path, fixture.value)
    monkeypatch.setattr(
        loader_module, "MAX_NEXTFLOW_JAR_BYTES", fixture.nextflow_jar.stat().st_size - 1
    )
    with pytest.raises(SchedulerConfigLoadError, match="byte budget"):
        load_trusted_scheduler_config(fixture.config_path)
    assert MAX_NEXTFLOW_JAR_BYTES == 128 * 1024 * 1024


def test_mutation_rechecks_reject_replaced_root_and_same_size_executable_change(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    fixture = scheduler_config_fixture
    loaded = load_trusted_scheduler_config(fixture.config_path)

    work = fixture.roots["work"]
    moved = work.with_name("work-old")
    work.rename(moved)
    work.mkdir(mode=0o700)
    with pytest.raises(SchedulerConfigLoadError, match="root changed"):
        verify_scheduler_root(loaded, "work")

    sbatch = fixture.executables["sbatch"]
    original = sbatch.read_bytes()
    changed = bytes([original[0] ^ 1]) + original[1:]
    assert len(changed) == len(original)
    sbatch.write_bytes(changed)
    sbatch.chmod(0o755)
    if sbatch.stat().st_mtime_ns == loaded.executables["sbatch"].mtime_ns:
        forced = loaded.executables["sbatch"].mtime_ns + 1_000_000_000
        os.utime(sbatch, ns=(forced, forced))
    with pytest.raises(SchedulerConfigLoadError, match="changed after startup"):
        verify_scheduler_executable(loaded, "sbatch")


def test_executable_hash_rejects_same_inode_size_with_restored_mtime(
    scheduler_config_fixture: SchedulerConfigFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = scheduler_config_fixture
    loaded = load_trusted_scheduler_config(fixture.config_path)
    binding = loaded.executables["sbatch"]
    path = fixture.executables["sbatch"]
    before = path.stat()
    original = path.read_bytes()
    changed = bytes([original[0] ^ 1]) + original[1:]

    path.write_bytes(changed)
    path.chmod(0o755)
    os.utime(path, ns=(before.st_atime_ns, binding.mtime_ns))
    mutated = path.stat()
    assert mutated.st_ino == binding.inode
    assert mutated.st_size == binding.size
    assert mutated.st_mtime_ns == binding.mtime_ns

    monkeypatch.setattr(loader_module, "_require_same_file", lambda _binding, _metadata: None)
    with pytest.raises(SchedulerConfigLoadError, match="hash changed"):
        verify_scheduler_executable(loaded, "sbatch")


def test_executable_hash_detects_a_file_changed_during_hashing(
    scheduler_config_fixture: SchedulerConfigFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = scheduler_config_fixture
    target = fixture.executables["sbatch"]
    target_inode = target.stat().st_ino
    real_hash = loader_module._sha256_descriptor
    mutated = False

    def hash_then_mutate(descriptor: int, maximum_bytes: int) -> str:
        nonlocal mutated
        result = real_hash(descriptor, maximum_bytes)
        if not mutated and os.fstat(descriptor).st_ino == target_inode:
            payload = target.read_bytes()
            target.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
            target.chmod(0o755)
            mutated = True
        return result

    monkeypatch.setattr(loader_module, "_sha256_descriptor", hash_then_mutate)
    with pytest.raises(SchedulerConfigLoadError, match="changed while it was hashed"):
        load_trusted_scheduler_config(fixture.config_path)
    assert mutated is True


def test_executable_hashing_is_bounded(
    scheduler_config_fixture: SchedulerConfigFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = scheduler_config_fixture.executables["sbatch"]
    monkeypatch.setattr(loader_module, "MAX_EXECUTABLE_BYTES", executable.stat().st_size - 1)

    with pytest.raises(SchedulerConfigLoadError, match="executable regular file"):
        load_trusted_scheduler_config(scheduler_config_fixture.config_path)
    assert MAX_EXECUTABLE_BYTES == 128 * 1024 * 1024


def test_hash_bound_rechecks_reject_same_size_config_and_jar_mutation(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    fixture = scheduler_config_fixture
    loaded = load_trusted_scheduler_config(fixture.config_path)

    config_payload = fixture.config_path.read_bytes()
    config_changed = config_payload.replace(b"hpc01-slurm", b"hpc02-slurm")
    assert len(config_changed) == len(config_payload)
    fixture.config_path.write_bytes(config_changed)
    fixture.config_path.chmod(0o600)
    with pytest.raises(SchedulerConfigLoadError, match="changed"):
        verify_scheduler_config_file(loaded)

    jar_payload = fixture.nextflow_jar.read_bytes()
    jar_changed = bytes([jar_payload[0] ^ 1]) + jar_payload[1:]
    assert len(jar_changed) == len(jar_payload)
    fixture.nextflow_jar.chmod(0o644)
    fixture.nextflow_jar.write_bytes(jar_changed)
    fixture.nextflow_jar.chmod(0o444)
    with pytest.raises(SchedulerConfigLoadError, match="changed"):
        verify_scheduler_nextflow_jar(loaded)


def test_verify_apis_reject_untrusted_objects(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    loaded = load_trusted_scheduler_config(scheduler_config_fixture.config_path)
    with pytest.raises(SchedulerConfigLoadError, match="trusted scheduler configuration"):
        verify_scheduler_config_file(object())  # type: ignore[arg-type]
    with pytest.raises(SchedulerConfigLoadError, match="trusted scheduler configuration"):
        verify_scheduler_root(object(), "read")  # type: ignore[arg-type]
    with pytest.raises(SchedulerConfigLoadError, match="root role"):
        verify_scheduler_root(loaded, [])  # type: ignore[arg-type]
    with pytest.raises(SchedulerConfigLoadError, match="root index"):
        verify_scheduler_root(loaded, "read", True)  # type: ignore[arg-type]
    with pytest.raises(SchedulerConfigLoadError, match="fixed executable role"):
        verify_scheduler_executable(loaded, "shell")  # type: ignore[arg-type]
    with pytest.raises(SchedulerConfigLoadError, match="trusted scheduler configuration"):
        verify_scheduler_nextflow_jar(object())  # type: ignore[arg-type]


def test_loader_has_no_process_network_environment_or_write_surface() -> None:
    source = inspect.getsource(loader_module)
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

    assert imported_roots <= {
        "__future__",
        "collections",
        "dataclasses",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "re",
        "stat",
        "types",
        "typing",
    }
    for forbidden in (
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "os.environ",
        "os.write",
        "os.mkdir",
        "os.unlink",
        "os.remove",
        "os.replace",
        "os.rename",
    ):
        assert forbidden not in source
    assert all(
        not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        )
        for node in ast.walk(tree)
    )


@pytest.mark.parametrize(
    "path",
    [
        Path("remote_executor/src/bioexec/main.py"),
        Path("remote_executor/src/bioexec/config.py"),
        Path("remote_executor/src/bioexec/protocol.py"),
        Path("remote_executor/src/bioexec/runner.py"),
    ],
)
def test_existing_v1_entrypoints_do_not_import_scheduler_loader(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert all(
        "scheduler_config_loader" not in (node.module or "")
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert all(
        all("scheduler_config_loader" not in alias.name for alias in node.names)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
    )


def test_bindings_and_trusted_config_block_public_construction_and_replace(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    with pytest.raises(TypeError):
        TrustedDirectoryBinding(  # type: ignore[call-arg]
            role="read",
            path=Path("/data/raw"),
            device=1,
            inode=2,
            owner=3,
            group=4,
            mode=0o750,
        )
    with pytest.raises(SchedulerConfigLoadError, match="construction is internal"):
        TrustedDirectoryBinding(
            _authority=object(),
            role="read",
            path=Path("/data/raw"),
            device=1,
            inode=2,
            owner=3,
            group=4,
            mode=0o750,
        )

    loaded = load_trusted_scheduler_config(scheduler_config_fixture.config_path)
    binding = loaded.read_roots[0]
    with pytest.raises(AttributeError):
        binding.inode = 4  # type: ignore[misc]
    with pytest.raises(ValueError, match="InitVar"):
        replace(binding, role="deploy")
    with pytest.raises(ValueError, match="InitVar"):
        replace(loaded, scheduler_policy_hash="0" * 64)


def test_internal_construction_rejects_cross_field_mismatches(
    scheduler_config_fixture: SchedulerConfigFixture,
) -> None:
    loaded = load_trusted_scheduler_config(scheduler_config_fixture.config_path)

    with pytest.raises(SchedulerConfigLoadError, match="policy hash"):
        replace(
            loaded,
            _authority=loader_module._CONFIG_AUTHORITY,
            scheduler_policy_hash="0" * 64,
        )

    wrong_role = replace(
        loaded.work_roots[0],
        _authority=loader_module._BINDING_AUTHORITY,
        role="read",
    )
    with pytest.raises(SchedulerConfigLoadError, match="role roots"):
        replace(
            loaded,
            _authority=loader_module._CONFIG_AUTHORITY,
            work_roots=(wrong_role,),
        )

    changed_executables = replace(
        loaded.contract.executables,
        java="/reviewed/other/java",
    )
    changed_contract = replace(loaded.contract, executables=changed_executables)
    with pytest.raises(SchedulerConfigLoadError, match="executable binding"):
        replace(
            loaded,
            _authority=loader_module._CONFIG_AUTHORITY,
            contract=changed_contract,
            contract_sha256=loader_module._scheduler_contract_sha256(changed_contract),
        )


def test_effective_execute_permission_uses_euid_and_group_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(loader_module.os, "geteuid", lambda: 1_000)
    monkeypatch.setattr(loader_module.os, "getegid", lambda: 100)
    monkeypatch.setattr(loader_module.os, "getgroups", lambda: [100, 200])

    euid_owned_other_only = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o401,
        st_size=1,
        st_uid=1_000,
        st_gid=300,
    )
    with pytest.raises(SchedulerConfigLoadError, match="executable regular file"):
        loader_module._require_executable(euid_owned_other_only)

    root_owned_owner_only = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o100,
        st_size=1,
        st_uid=0,
        st_gid=0,
    )
    with pytest.raises(SchedulerConfigLoadError, match="executable regular file"):
        loader_module._require_executable(root_owned_owner_only)

    group_executable = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o010,
        st_size=1,
        st_uid=0,
        st_gid=100,
    )
    loader_module._require_executable(group_executable)


def test_root_effective_execute_permission_accepts_any_execute_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(loader_module.os, "geteuid", lambda: 0)
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o001,
        st_size=1,
        st_uid=0,
        st_gid=0,
    )
    loader_module._require_executable(metadata)


def test_python39_v1_import_graph_does_not_load_scheduler_loader() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "import bioexec.main\n"
        "import bioexec.config\n"
        "import bioexec.protocol\n"
        "import bioexec.preflight\n"
        "import bioexec.deployment\n"
        "import bioexec.runner\n"
        "import bioexec.state\n"
        "import bioexec.commands\n"
        "assert 'bioexec.scheduler_config_loader' not in sys.modules\n"
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
