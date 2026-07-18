from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import stat
import sys
import time
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "generate_supply_chain_inventory.py"


def _module() -> object:
    spec = importlib.util.spec_from_file_location("supply_chain_inventory_script", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


inventory = _module()


def _record(
    *,
    platform: str = "linux-64",
    name: str = "python",
    version: str = "3.12.11",
) -> dict[str, object]:
    filename = f"{name}-{version}-h1234567_0.conda"
    channel = "conda-forge"
    subdir = platform
    return {
        "build_number": 0,
        "build_string": "h1234567_0",
        "channel": f"https://conda.anaconda.org/{channel}/{subdir}",
        "depends": [],
        "fn": filename,
        "license": "Python-2.0",
        "md5": "1" * 32,
        "name": name,
        "sha256": "2" * 64,
        "size": 1234,
        "subdir": subdir,
        "timestamp": 1_700_000_000_000,
        "url": f"https://conda.anaconda.org/{channel}/{subdir}/{filename}",
        "version": version,
    }


def test_environment_definition_has_only_exact_direct_pins() -> None:
    value, payload = inventory._environment_definition(REPOSITORY_ROOT)

    assert payload
    assert len(value["direct"]) == 20
    assert {item["name"] for item in value["direct"]} >= {
        "nextflow",
        "python",
        "python-build",
    }
    assert all(item["version"] and "=" not in item["version"] for item in value["direct"])


@pytest.mark.parametrize(
    "url",
    [
        "https://token@conda.anaconda.org/conda-forge/linux-64/python.conda",
        "https://conda.anaconda.org/conda-forge/linux-64/python.conda?token=secret",
        "http://conda.anaconda.org/conda-forge/linux-64/python.conda",
        "https://evil.example/conda-forge/linux-64/python.conda",
        "https://conda.anaconda.org/other/linux-64/python.conda",
        "https://conda.anaconda.org/conda-forge/osx-arm64/python.conda",
        "file:///private/cache/python.conda",
    ],
)
def test_package_url_rejects_credentials_queries_channels_and_platforms(url: str) -> None:
    with pytest.raises(inventory.SupplyChainError, match="UNSAFE_PACKAGE_URL"):
        inventory._validate_url(url, target_platform="linux-64")


def test_package_record_rejects_hash_and_direct_pin_mismatch() -> None:
    bad_hash = _record()
    bad_hash["sha256"] = "not-a-sha256"
    with pytest.raises(inventory.SupplyChainError, match="INVALID_PACKAGE_HASH"):
        inventory._normalize_records(
            [bad_hash],
            target_platform="linux-64",
            direct=[{"name": "python", "version": "3.12.11"}],
        )

    with pytest.raises(inventory.SupplyChainError, match="DIRECT_DEPENDENCY_PIN_MISMATCH"):
        inventory._normalize_records(
            [_record()],
            target_platform="linux-64",
            direct=[{"name": "python", "version": "3.12.10"}],
        )

    boolean_integer = _record()
    boolean_integer["build_number"] = True
    with pytest.raises(inventory.SupplyChainError, match="INVALID_PACKAGE_RECORD"):
        inventory._normalize_records(
            [boolean_integer],
            target_platform="linux-64",
            direct=[{"name": "python", "version": "3.12.11"}],
        )


def test_package_record_normalizes_solver_null_dependencies_only() -> None:
    no_dependencies = _record()
    no_dependencies["depends"] = None
    normalized = inventory._normalize_records(
        [no_dependencies],
        target_platform="linux-64",
        direct=[{"name": "python", "version": "3.12.11"}],
    )
    assert normalized[0]["depends"] == []

    invalid_dependencies = _record()
    invalid_dependencies["depends"] = "openssl"
    with pytest.raises(inventory.SupplyChainError, match="INVALID_PACKAGE_DEPENDENCIES"):
        inventory._normalize_records(
            [invalid_dependencies],
            target_platform="linux-64",
            direct=[{"name": "python", "version": "3.12.11"}],
        )

    missing_dependency = _record()
    missing_dependency["depends"] = ["definitely-not-present >=1"]
    with pytest.raises(inventory.SupplyChainError, match="PACKAGE_DEPENDENCY_NOT_LOCKED"):
        inventory._normalize_records(
            [missing_dependency],
            target_platform="linux-64",
            direct=[{"name": "python", "version": "3.12.11"}],
        )


def test_conda_package_names_may_have_a_leading_underscore() -> None:
    record = _record(name="_openmp_mutex", version="4.5")
    normalized = inventory._normalize_records(
        [record],
        target_platform="linux-64",
        direct=[{"name": "_openmp_mutex", "version": "4.5"}],
    )
    assert normalized[0]["name"] == "_openmp_mutex"


def test_linux_solver_environment_fixes_platform_and_virtual_packages(tmp_path: Path) -> None:
    environment = inventory._controlled_environment(tmp_path, "linux-64")

    assert environment["CONDA_SUBDIR"] == "linux-64"
    assert environment["CONDA_OVERRIDE_LINUX"] == "5.15"
    assert environment["CONDA_OVERRIDE_GLIBC"] == "2.17"
    assert inventory.TARGETS["linux-64"] == (
        "__unix=0=0",
        "__linux=5.15=0",
        "__glibc=2.17=0",
        "__archspec=1=x86_64-v2",
    )


def test_explicit_lock_must_match_inventory_hashes() -> None:
    direct = [{"name": "python", "version": "3.12.11"}]
    normalized = inventory._normalize_records(
        [_record()], target_platform="linux-64", direct=direct
    )
    value = {
        "direct_dependencies": direct,
        "format_version": inventory.FORMAT_VERSION,
        "native_runtime_validation": {
            "reason": "generated_by_cross_platform_metadata_solve_only",
            "status": "pending",
        },
        "packages": normalized,
        "resolution_status": "resolved_cross_platform",
        "source_environment_sha256": "3" * 64,
        "target_platform": "linux-64",
        "virtual_packages": list(inventory.TARGETS["linux-64"]),
    }
    explicit = inventory._render_explicit("linux-64", normalized)
    inventory._verify_lock_pair(explicit, value, platform="linux-64")

    changed = explicit.replace(b"#" + b"1" * 32, b"#" + b"4" * 32)
    with pytest.raises(inventory.SupplyChainError, match="EXPLICIT_INVENTORY_MISMATCH"):
        inventory._verify_lock_pair(changed, value, platform="linux-64")

    forged_version = copy.deepcopy(value)
    forged_version["packages"][0]["version"] = "999.0"
    with pytest.raises(inventory.SupplyChainError, match="PACKAGE_FILENAME_METADATA_MISMATCH"):
        inventory._verify_lock_pair(explicit, forged_version, platform="linux-64")


def test_create_only_group_publication_refuses_existing_directory(tmp_path: Path) -> None:
    output = tmp_path / "new-inventory"
    inventory._publish_create_only(output, {"evidence.json": b"{}\n"})
    assert (output / "evidence.json").read_bytes() == b"{}\n"

    with pytest.raises(inventory.SupplyChainError, match="CREATE_ONLY_OUTPUT_EXISTS"):
        inventory._reject_existing_output(output)

    with pytest.raises(inventory.SupplyChainError, match="CREATE_ONLY_PUBLICATION_FAILED"):
        inventory._publish_create_only(output, {"evidence.json": b'{"changed":true}\n'})
    assert (output / "evidence.json").read_bytes() == b"{}\n"


def test_private_path_is_rejected_before_publication(tmp_path: Path) -> None:
    repository = tmp_path / "private-repository"
    repository.mkdir()
    payload = {"artifact.json": f'{{"path":"{repository}"}}\n'.encode()}

    with pytest.raises(inventory.SupplyChainError, match="PRIVATE_DATA_IN_GENERATED_ARTIFACT"):
        inventory._assert_no_private_data(payload, repository)


def test_subprocess_output_is_bounded_while_process_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(inventory, "MAX_SOLVER_OUTPUT_BYTES", 1024)
    with pytest.raises(inventory.SupplyChainError, match="BOUNDED_SUBPROCESS_FAILED"):
        inventory._run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
            cwd=tmp_path,
            environment={"PATH": "/usr/bin:/bin"},
            timeout=5,
        )


def test_container_approval_requires_digest_and_review_evidence() -> None:
    value = inventory._container_inventory(REPOSITORY_ROOT)
    assert len(value["containers"]) == 3
    assert {item["license_review"]["status"] for item in value["containers"]} == {"pending"}
    assert value["release_readiness"]["status"] == "blocked"

    forged = copy.deepcopy(value)
    forged["containers"][0]["license_review"] = {
        "evidence_sha256": "f" * 64,
        "reviewed_at": "2026-07-18T00:00:00Z",
        "reviewer": "forged-reviewer",
        "scope": "exact_container_contents",
        "status": "approved",
    }
    forged["containers"][0]["digest_verification"] = {
        "evidence_sha256": "e" * 64,
        "status": "verified",
    }
    with pytest.raises(inventory.SupplyChainError, match="UNSUPPORTED_CONTAINER_APPROVAL"):
        inventory._validate_container_inventory(forged)


def test_container_inventory_rejects_empty_duplicate_identity_and_ready_claim() -> None:
    value = inventory._container_inventory(REPOSITORY_ROOT)

    empty = copy.deepcopy(value)
    empty["containers"] = []
    with pytest.raises(inventory.SupplyChainError, match="INVALID_CONTAINER_INVENTORY"):
        inventory._validate_container_inventory(empty)

    duplicate = copy.deepcopy(value)
    duplicate["containers"][1] = copy.deepcopy(duplicate["containers"][0])
    with pytest.raises(inventory.SupplyChainError, match="INVALID_CONTAINER_INVENTORY"):
        inventory._validate_container_inventory(duplicate)

    claimed_ready = copy.deepcopy(value)
    claimed_ready["release_readiness"] = {"reason": "forged", "status": "ready"}
    with pytest.raises(inventory.SupplyChainError, match="INVALID_CONTAINER_INVENTORY"):
        inventory._validate_container_inventory(claimed_ready)


def _write_zipapp(path: Path, member_name: str) -> None:
    path.write_bytes(b"#!/usr/bin/env python3\n")
    info = zipfile.ZipInfo(member_name, date_time=time.gmtime(inventory.SOURCE_DATE_EPOCH)[:6])
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(path, mode="a") as archive:
        archive.writestr(info, b"payload")


def test_zipapp_inventory_rejects_traversal_and_symlink(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.pyz"
    _write_zipapp(traversal, "../escape.py")
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_METADATA"):
        inventory._inspect_zipapp(traversal, expected_members={"../escape.py": b"payload"})

    symlink = tmp_path / "symlink.pyz"
    symlink.write_bytes(b"#!/usr/bin/env python3\n")
    info = zipfile.ZipInfo("module.py", date_time=time.gmtime(inventory.SOURCE_DATE_EPOCH)[:6])
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(symlink, mode="a") as archive:
        archive.writestr(info, b"target")
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_METADATA"):
        inventory._inspect_zipapp(symlink, expected_members={"module.py": b"target"})


@pytest.mark.parametrize("name", ["bioexec/./main.py", "bioexec/bad\nname.py", "/main.py"])
def test_zipapp_member_names_are_canonical_printable_relative_paths(name: str) -> None:
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_MEMBER_NAME"):
        inventory._validate_zip_member_name(name)


def test_zipapp_source_tree_rejects_symlink(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "remote_probe" / "src" / "bioprobe"
    source.mkdir(parents=True)
    (repository / "LICENSE").write_text("license")
    target = tmp_path / "outside.py"
    target.write_text("secret = True\n")
    (source / "escape.py").symlink_to(target)

    with pytest.raises(inventory.SupplyChainError, match="UNSAFE_ZIPAPP_SOURCE"):
        inventory._expected_zip_members(repository, "bioprobe", "remote_probe")


def test_source_reader_rejects_symlinked_parent_component(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "source.txt").write_text("public")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises(inventory.SupplyChainError, match="UNSAFE_SOURCE_INPUT"):
        inventory._read_source(alias / "source.txt")


def test_offline_zipapp_inventory_deeply_validates_members() -> None:
    value = inventory._zipapp_inventory(REPOSITORY_ROOT)
    inventory._validate_zipapp_inventory(value)

    forged_mode = copy.deepcopy(value)
    forged_mode["artifacts"][0]["members"][0]["mode"] = "0777"
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_INVENTORY"):
        inventory._validate_zipapp_inventory(forged_mode)

    forged_member = copy.deepcopy(value)
    forged_member["artifacts"][0]["members"][2]["name"] = "../escape.py"
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_INVENTORY"):
        inventory._validate_zipapp_inventory(forged_member)

    shadow_claim = copy.deepcopy(value)
    shadow_claim["release_ready"] = True
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_INVENTORY"):
        inventory._validate_zipapp_inventory(shadow_claim)

    forged_remote = copy.deepcopy(value)
    forged_remote["native_remote_host_acceptance"]["reason"] = "validated_on_remote_host"
    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_INVENTORY"):
        inventory._validate_zipapp_inventory(forged_remote)


def _tampered_bundle(tmp_path: Path) -> Path:
    source = REPOSITORY_ROOT / "environments" / "locks"
    destination = tmp_path / "locks"
    shutil.copytree(source, destination)
    return destination


def _reseal(directory: Path) -> None:
    payloads = {
        path.name: path.read_bytes() for path in directory.iterdir() if path.name != "SHA256SUMS"
    }
    (directory / "SHA256SUMS").write_bytes(inventory.checksum_payloads(payloads))


def test_offline_verify_rejects_resealed_shadow_claim(tmp_path: Path) -> None:
    directory = _tampered_bundle(tmp_path)
    path = directory / "remote-zipapps.json"
    value = json.loads(path.read_text())
    value["release_ready"] = True
    path.write_bytes(inventory._json_bytes(value))
    _reseal(directory)

    with pytest.raises(inventory.SupplyChainError, match="INVALID_ZIPAPP_INVENTORY"):
        inventory.verify(directory=directory)


def test_offline_verify_rejects_resealed_readme_claim(tmp_path: Path) -> None:
    directory = _tampered_bundle(tmp_path)
    (directory / "README.md").write_text("Native acceptance passed.\n")
    _reseal(directory)

    with pytest.raises(inventory.SupplyChainError, match="INVALID_SUPPLY_CHAIN_README"):
        inventory.verify(directory=directory)


def test_offline_verify_rejects_resealed_source_inventory_claim(tmp_path: Path) -> None:
    directory = _tampered_bundle(tmp_path)
    path = directory / "remote-zipapps.json"
    value = json.loads(path.read_text())
    value["artifacts"][0]["archive_sha256"] = "a" * 64
    path.write_bytes(inventory._json_bytes(value))
    _reseal(directory)

    with pytest.raises(inventory.SupplyChainError, match="ZIPAPP_SOURCE_INVENTORY_MISMATCH"):
        inventory.verify(directory=directory)


def test_offline_reader_rejects_symlinked_artifact(tmp_path: Path) -> None:
    directory = _tampered_bundle(tmp_path)
    target = tmp_path / "outside.json"
    target.write_text("{}\n")
    artifact = directory / "containers.json"
    artifact.unlink()
    artifact.symlink_to(target)

    with pytest.raises(inventory.SupplyChainError, match="UNSAFE_INVENTORY_FILE"):
        inventory.verify(directory=directory)


def test_committed_supply_chain_inventory_verifies_fully_offline() -> None:
    result = inventory.verify(directory=REPOSITORY_ROOT / "environments" / "locks")

    assert result["status"] == "supply_chain_inventory_verified_offline"
    assert result["package_counts"]["linux-64"] > 20
    assert result["package_counts"]["osx-arm64"] > 20
