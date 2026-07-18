#!/usr/bin/env python3
"""Verify an sdist and smoke-test an isolated easy-pipe installation."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tarfile
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import Any

import biopipe
from biopipe.errors import BioPipeError
from biopipe.io import read_model
from biopipe.manifests import require_valid_manifest
from biopipe.models import DatasetManifest
from biopipe.registry import load_default_registry
from biopipe.version import MVP_SCHEMA_VERSION

_EXPECTED_SOURCE_ID = "package-install-synthetic"
_EXPECTED_SOURCE_ROOT = "/synthetic/package-install"
_EXPECTED_SAMPLE_ID = "synthetic_sample"
_MAX_REVIEW_COPY_BYTES = 8 * 1024 * 1024
_MAX_INSTALLED_RESOURCE_DEPTH = 16
_MAX_INSTALLED_RESOURCE_ENTRIES = 2_048
_MAX_INSTALLED_RESOURCE_FILES = 512


class VerificationError(RuntimeError):
    """Raised when a distribution or installed-package invariant fails."""


def _parse_args() -> argparse.Namespace:
    repository_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=repository_default,
        help="Reviewed source tree used to build the supplied sdist.",
    )
    parser.add_argument(
        "--sdist",
        type=Path,
        required=True,
        help="Exact easy-pipe .tar.gz source distribution to inspect.",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=repository_default / "tests/fixtures/package_install/dataset.manifest.json",
        help="Reviewed synthetic full-manifest fixture.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        required=True,
        help="New or empty directory for the plan and generated project.",
    )
    return parser.parse_args()


def _regular_files_with_suffixes(
    repository_root: Path,
    relative_root: str,
    suffixes: frozenset[str],
) -> list[Path]:
    source_root = repository_root / relative_root
    if source_root.is_symlink() or not source_root.is_dir():
        raise VerificationError("review-copy root must be a real directory")
    selected: list[Path] = []
    for path in source_root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise VerificationError("review-copy source sets must not contain symlinks")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise VerificationError("review-copy source sets must contain only regular files")
        if path.suffix not in suffixes:
            continue
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(repository_root):
            raise VerificationError("review-copy source escaped the repository")
        selected.append(path)
    return sorted(selected)


def _require_regular_source_file(repository_root: Path, path: Path) -> Path:
    try:
        relative = path.relative_to(repository_root)
    except ValueError as exc:
        raise VerificationError("reviewed source role escaped the repository") from exc
    current = repository_root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise VerificationError("reviewed source roles must not contain symlinks")
    if not path.is_file() or not stat.S_ISREG(path.lstat().st_mode):
        raise VerificationError("reviewed source role must be a regular file")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(repository_root):
        raise VerificationError("reviewed source role escaped the repository")
    return path


def _review_copy_paths(repository_root: Path) -> tuple[Path, ...]:
    templates = _regular_files_with_suffixes(
        repository_root,
        "templates",
        frozenset({".j2"}),
    )
    registry = _regular_files_with_suffixes(
        repository_root,
        "registry",
        frozenset({".yaml", ".yml"}),
    )
    environments = _regular_files_with_suffixes(
        repository_root,
        "environments",
        frozenset({".yml", ".yaml", ".txt", ".json"}),
    )
    environments.extend(
        [
            _require_regular_source_file(
                repository_root,
                repository_root / "environments/locks/README.md",
            ),
            _require_regular_source_file(
                repository_root,
                repository_root / "environments/locks/SHA256SUMS",
            ),
        ]
    )
    if not templates or not registry or not environments:
        raise VerificationError("review-copy source sets must all be non-empty")
    return tuple(templates + registry + environments)


def _allowed_evidence_paths(repository_root: Path) -> tuple[Path, ...]:
    evidence_root = repository_root / "release-evidence"
    fixed = [
        _require_regular_source_file(repository_root, evidence_root / ".gitignore"),
        _require_regular_source_file(repository_root, evidence_root / "README.md"),
    ]
    templates = _regular_files_with_suffixes(
        repository_root,
        "release-evidence/template",
        frozenset({".md", ".json", ".txt"}),
    )
    paths = fixed + templates
    if not templates:
        raise VerificationError("release-evidence scaffolding is incomplete")
    return tuple(paths)


def _relative_archive_members(sdist: Path) -> dict[PurePosixPath, tarfile.TarInfo]:
    if not sdist.is_file() or not sdist.name.endswith(".tar.gz"):
        raise VerificationError("sdist must be an existing .tar.gz file")
    members: dict[PurePosixPath, tarfile.TarInfo] = {}
    roots: set[str] = set()
    with tarfile.open(sdist, mode="r:gz") as archive:
        for member in archive.getmembers():
            archive_path = PurePosixPath(member.name)
            if archive_path.is_absolute() or ".." in archive_path.parts:
                raise VerificationError("sdist contains an unsafe member path")
            if not archive_path.parts or archive_path.parts[0] in {"", "."}:
                raise VerificationError("sdist member paths must have one package root")
            roots.add(archive_path.parts[0])
            if len(archive_path.parts) == 1:
                if not member.isdir():
                    raise VerificationError("sdist package root must be a directory")
                continue
            relative = PurePosixPath(*archive_path.parts[1:])
            if relative in members:
                raise VerificationError("sdist contains a duplicate member path")
            if not (member.isfile() or member.isdir()):
                raise VerificationError("sdist contains a link or special member")
            members[relative] = member
        if len(roots) != 1:
            raise VerificationError("sdist must contain exactly one package root")
    return members


def _read_archive_file(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > _MAX_REVIEW_COPY_BYTES:
        raise VerificationError("sdist review-copy member has an invalid type or size")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise VerificationError("sdist review-copy member could not be read")
    payload = extracted.read(_MAX_REVIEW_COPY_BYTES + 1)
    if len(payload) != member.size or len(payload) > _MAX_REVIEW_COPY_BYTES:
        raise VerificationError("sdist review-copy member size did not match its header")
    return payload


def _verify_sdist(repository_root: Path, sdist: Path) -> None:
    expected_sources = _review_copy_paths(repository_root)
    allowed_evidence = _allowed_evidence_paths(repository_root)
    members = _relative_archive_members(sdist)
    expected_evidence_names = {
        PurePosixPath(path.relative_to(repository_root).as_posix()) for path in allowed_evidence
    }
    allowed_evidence_directories = {PurePosixPath("release-evidence")}
    for name in expected_evidence_names:
        allowed_evidence_directories.update(name.parents)

    for relative, member in members.items():
        if relative.parts[0] != "release-evidence":
            continue
        if member.isfile() and relative not in expected_evidence_names:
            raise VerificationError("sdist contains generated or unexpected release evidence")
        if member.isdir() and relative not in allowed_evidence_directories:
            raise VerificationError("sdist contains a generated release-evidence directory")

    expected_files = expected_sources + allowed_evidence
    with tarfile.open(sdist, mode="r:gz") as archive:
        for source in expected_files:
            relative = PurePosixPath(source.relative_to(repository_root).as_posix())
            expected_member = members.get(relative)
            if expected_member is None:
                raise VerificationError("sdist is missing a reviewed source role")
            if _read_archive_file(archive, expected_member) != source.read_bytes():
                raise VerificationError("sdist reviewed source bytes do not match")


def _assert_isolated_install() -> None:
    if not sys.flags.isolated:
        raise VerificationError("run this helper with the installed interpreter's -I option")
    package_file = Path(biopipe.__file__).resolve()
    environment_root = Path(sys.prefix).resolve()
    if not package_file.is_relative_to(environment_root):
        raise VerificationError("biopipe was not imported from the isolated environment")


def _installed_resource_files(
    root: Traversable,
    suffixes: frozenset[str],
) -> dict[PurePosixPath, bytes]:
    if not root.is_dir():
        raise VerificationError("installed resource root is missing")
    selected: dict[PurePosixPath, bytes] = {}
    pending: list[tuple[PurePosixPath, Traversable, int]] = [(PurePosixPath(), root, 0)]
    entry_count = 0
    while pending:
        relative_root, current, depth = pending.pop()
        if depth > _MAX_INSTALLED_RESOURCE_DEPTH:
            raise VerificationError("installed resource hierarchy is too deep")
        entries = sorted(current.iterdir(), key=lambda entry: entry.name)
        for entry in entries:
            entry_count += 1
            if entry_count > _MAX_INSTALLED_RESOURCE_ENTRIES:
                raise VerificationError("installed resource hierarchy contains too many entries")
            name = entry.name
            if not name or name in {".", ".."} or PurePosixPath(name).name != name:
                raise VerificationError("installed resource has an unsafe name")
            if isinstance(entry, Path) and entry.is_symlink():
                raise VerificationError("installed resources must not contain symlinks")
            relative = relative_root / name
            if entry.is_dir():
                pending.append((relative, entry, depth + 1))
                continue
            if not entry.is_file():
                raise VerificationError("installed resources must contain only regular files")
            if relative.suffix not in suffixes:
                continue
            if relative in selected:
                raise VerificationError("installed resource set contains a duplicate path")
            with entry.open("rb") as stream:
                payload = stream.read(_MAX_REVIEW_COPY_BYTES + 1)
            if len(payload) > _MAX_REVIEW_COPY_BYTES:
                raise VerificationError("installed resource exceeds the review size limit")
            selected[relative] = payload
            if len(selected) > _MAX_INSTALLED_RESOURCE_FILES:
                raise VerificationError("installed resource set contains too many files")
    return selected


def _require_exact_resource_set(
    installed: dict[PurePosixPath, bytes],
    reviewed: dict[PurePosixPath, bytes],
    role: str,
) -> None:
    if installed.keys() != reviewed.keys():
        raise VerificationError(f"installed {role} resource set does not match review copies")
    if any(installed[name] != payload for name, payload in reviewed.items()):
        raise VerificationError(f"installed {role} bytes do not match review copies")


def _verify_installed_review_copies(repository_root: Path) -> None:
    template_root = repository_root / "templates/nextflow"
    installed_templates = resources.files("biopipe.compiler").joinpath("_templates")
    reviewed_sources = _review_copy_paths(repository_root)
    reviewed_templates = [
        path for path in reviewed_sources if path.is_relative_to(repository_root / "templates")
    ]
    reviewed_template_payloads = {
        PurePosixPath(path.relative_to(template_root).as_posix()): path.read_bytes()
        for path in reviewed_templates
    }
    installed_template_payloads = _installed_resource_files(
        installed_templates,
        frozenset({".j2"}),
    )
    _require_exact_resource_set(
        installed_template_payloads,
        reviewed_template_payloads,
        "compiler template",
    )

    registry_root = repository_root / "registry/components"
    installed_registry = resources.files("biopipe.registry").joinpath("data")
    reviewed_registry = [
        path for path in reviewed_sources if path.is_relative_to(repository_root / "registry")
    ]
    reviewed_registry_payloads = {
        PurePosixPath(path.relative_to(registry_root).as_posix()): path.read_bytes()
        for path in reviewed_registry
    }
    installed_registry_payloads = _installed_resource_files(
        installed_registry,
        frozenset({".yaml", ".yml"}),
    )
    _require_exact_resource_set(
        installed_registry_payloads,
        reviewed_registry_payloads,
        "registry",
    )


def _safe_cli_environment() -> dict[str, str]:
    environment = {
        "PATH": str(Path(sys.executable).resolve().parent),
        "PYTHONNOUSERSITE": "1",
    }
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if value := os.environ.get(name):
                environment[name] = value
    return environment


def _run_cli(work_dir: Path, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-I", "-m", "biopipe", *arguments],
        cwd=work_dir,
        env=_safe_cli_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise VerificationError("installed biopipe command failed")
    try:
        result = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise VerificationError("installed biopipe command did not return JSON") from exc
    if not isinstance(result, dict):
        raise VerificationError("installed biopipe command returned a non-object")
    return result


def _verify_fixture(fixture: Path) -> None:
    manifest = require_valid_manifest(read_model(fixture, DatasetManifest))
    if (
        manifest.source.source_id != _EXPECTED_SOURCE_ID
        or manifest.source.root != _EXPECTED_SOURCE_ROOT
        or len(manifest.samples) != 1
        or manifest.samples[0].sample_id != _EXPECTED_SAMPLE_ID
        or manifest.samples[0].original_sample_name != _EXPECTED_SAMPLE_ID
        or manifest.privacy.filenames_may_contain_identifiers
        or manifest.privacy.raw_content_exported
    ):
        raise VerificationError("package-install fixture is not the fixed synthetic dataset")
    lanes = manifest.samples[0].lanes
    if len(lanes) != 1 or not lanes[0].read1.startswith(f"{_EXPECTED_SOURCE_ROOT}/"):
        raise VerificationError("package-install fixture escaped the synthetic source root")


def _prepare_work_directory(work_dir: Path) -> Path:
    destination = work_dir.absolute()
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise VerificationError("work directory must be a real directory")
    if destination.exists():
        if next(destination.iterdir(), None) is not None:
            raise VerificationError("work directory must be empty")
    else:
        destination.mkdir(parents=True)
    return destination


def _verify_installed_commands(fixture: Path, work_dir: Path) -> None:
    version = _run_cli(work_dir, "version", "--json")
    if (
        version.get("controller_version") != biopipe.__version__
        or version.get("registry_version") != version.get("registry_version_expected")
        or version.get("schema_version") != MVP_SCHEMA_VERSION
    ):
        raise VerificationError("installed version identities are inconsistent")

    catalog = _run_cli(work_dir, "schema", "list", "--json")
    schemas = catalog.get("schemas")
    if (
        catalog.get("schema_version") != MVP_SCHEMA_VERSION
        or not isinstance(schemas, list)
        or catalog.get("schema_count") != len(schemas)
        or not schemas
    ):
        raise VerificationError("installed schema catalog is inconsistent")
    catalog_resource = resources.files("biopipe").joinpath("schema_v1/catalog.json")
    if not catalog_resource.is_file() or json.loads(catalog_resource.read_text()) != catalog:
        raise VerificationError("installed schema catalog resource does not match the CLI")
    if load_default_registry().version != version["registry_version"]:
        raise VerificationError("installed registry resource does not match the version command")

    plan_path = work_dir / "planned/pipeline.spec.yaml"
    planned = _run_cli(
        work_dir,
        "plan",
        "--manifest",
        str(fixture.resolve()),
        "--goal",
        "fastq-qc",
        "--project-name",
        "package-install-smoke",
        "--output",
        str(plan_path),
        "--json",
    )
    if planned.get("status") != "planned":
        raise VerificationError("installed package did not produce a plan")

    generated_path = work_dir / "generated"
    generated = _run_cli(
        work_dir,
        "generate",
        "--spec",
        str(plan_path),
        "--output",
        str(generated_path),
        "--json",
    )
    if generated.get("status") != "generated":
        raise VerificationError("installed package did not generate a project")
    required_outputs = (
        generated_path / "main.nf",
        generated_path / "modules/fastqc/raw.nf",
        generated_path / "LICENSE",
    )
    if not all(path.is_file() and path.stat().st_size > 0 for path in required_outputs):
        raise VerificationError("installed package generated an incomplete project")


def main() -> int:
    args = _parse_args()
    try:
        repository_root = args.repository_root.resolve(strict=True)
        fixture = args.fixture.resolve(strict=True)
        sdist = args.sdist.resolve(strict=True)
        _assert_isolated_install()
        _verify_fixture(fixture)
        _verify_sdist(repository_root, sdist)
        _verify_installed_review_copies(repository_root)
        work_dir = _prepare_work_directory(args.work_dir)
        _verify_installed_commands(fixture, work_dir)
    except (BioPipeError, OSError, ValueError, VerificationError, tarfile.TarError) as exc:
        print(json.dumps({"status": "package_verification_failed", "reason": str(exc)}))
        return 2
    print(
        json.dumps(
            {
                "installed_origin": "isolated_environment",
                "plan_generate": "passed",
                "release_evidence_scope": "scaffolding_only",
                "resources": "verified",
                "sdist_review_copies": "verified",
                "status": "package_verified",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
