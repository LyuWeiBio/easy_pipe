"""Deterministic production-only project deployment bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model
from biopipe.models import DatasetManifest, ExecutionPlan, PipelineSpec, SoftwareLock
from biopipe.planner import reconstruct_planned_pipeline
from biopipe.registry import load_default_registry
from biopipe.validation import validate_generated_project

_MAX_FILE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 48 * 1024 * 1024
_MAX_FILES: Final[int] = 128
_FIXED_FILES: Final[frozenset[str]] = frozenset(
    {
        "LICENSE",
        "README.md",
        "assets/samplesheet.csv",
        "audit/events.jsonl",
        "conf/base.config",
        "conf/local.config",
        "dataset.manifest.resolved.json",
        "execution.plan.yaml",
        "main.nf",
        "nextflow.config",
        "pipeline.spec.yaml",
        "software.lock.yaml",
    }
)
_REQUIRED_PRODUCTION_FILES: Final[frozenset[str]] = frozenset(
    {
        "LICENSE",
        "main.nf",
        "nextflow.config",
        "pipeline.spec.yaml",
        "execution.plan.yaml",
        "software.lock.yaml",
        "dataset.manifest.resolved.json",
        "assets/samplesheet.csv",
        "conf/base.config",
        "conf/local.config",
        "modules/fastqc/raw.nf",
        "modules/multiqc/main.nf",
    }
)


@dataclass(frozen=True, slots=True)
class DeploymentFile:
    """One bounded generated file sent to the remote execution agent."""

    path: str
    size: int
    sha256: str
    content: bytes

    def protocol_payload(self) -> dict[str, str | int]:
        """Return the fixed JSON transport representation."""

        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "content_base64": base64.b64encode(self.content).decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class DeploymentBundle:
    """An immutable file set with a canonical aggregate digest."""

    files: tuple[DeploymentFile, ...]
    bundle_hash: str

    def protocol_files(self) -> list[dict[str, str | int]]:
        """Return files in the digest-bound canonical order."""

        return [item.protocol_payload() for item in self.files]

    def content(self, relative_path: str) -> bytes:
        """Return one required file from the immutable snapshot."""

        for item in self.files:
            if item.path == relative_path:
                return item.content
        raise KeyError(relative_path)


def build_deployment_bundle(
    project_directory: str | Path,
    *,
    check_output_conflict: bool = True,
) -> DeploymentBundle:
    """Recompile reviewed models and package only production execution files.

    The original generated source is first statically validated, then its strict
    domain models are reconstructed through the reviewed compiler in an isolated
    directory. Runtime, report, nf-test, and synthetic-fixture files are never
    deployed.
    """

    project = Path(project_directory).expanduser().absolute()
    validation = validate_generated_project(
        project,
        check_output_conflict=check_output_conflict,
    )
    if validation.status != "valid":
        raise BioPipeError(
            ErrorCode.DEPLOYMENT_FAILED,
            "The generated project is not valid for deployment.",
            context={"finding_codes": [finding.code.value for finding in validation.findings]},
            remediation=["Regenerate, validate, and test the project before preflight."],
        )
    try:
        manifest = read_model(project / "dataset.manifest.resolved.json", DatasetManifest)
        spec = read_model(project / "pipeline.spec.yaml", PipelineSpec)
        execution_plan = read_model(project / "execution.plan.yaml", ExecutionPlan)
        software_lock = read_model(project / "software.lock.yaml", SoftwareLock)
        registry = load_default_registry()
        planned = reconstruct_planned_pipeline(
            spec,
            execution_plan,
            software_lock,
            registry=registry,
        )
        with tempfile.TemporaryDirectory(prefix="biopipe-m5-deploy-") as temporary:
            snapshot = Path(temporary) / "project"
            NextflowCompiler().compile_planned(
                snapshot,
                manifest=manifest,
                planned=planned,
                registry=registry,
            )
            files = _read_production_files(snapshot)
    except BioPipeError:
        raise
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.DEPLOYMENT_FAILED,
            "A production deployment snapshot could not be created.",
            remediation=["Regenerate the complete project and retry."],
        ) from exc
    return DeploymentBundle(files=files, bundle_hash=_bundle_hash(files))


def hash_frozen_deployment_snapshot(project_directory: str | Path) -> str:
    """Hash the validated production snapshot without compiling or packaging it.

    Runtime audit records are excluded because deployment compilation deterministically
    recreates only the first ``PIPELINE_GENERATED`` record.
    """

    project = Path(project_directory).expanduser().absolute()
    try:
        metadata: list[dict[str, str | int]] = []
        total = 0
        candidates = sorted(path for path in project.rglob("*") if path.is_file())
        for candidate in candidates:
            relative = candidate.relative_to(project).as_posix()
            if not _is_production_file(relative):
                continue
            payload = _read_regular_file(candidate)
            if relative == "audit/events.jsonl":
                first_line_end = payload.find(b"\n")
                if first_line_end <= 0:
                    raise ValueError("generation audit record is incomplete")
                payload = payload[: first_line_end + 1]
            if len(payload) > _MAX_FILE_BYTES:
                raise ValueError("deployment file exceeds its size limit")
            total += len(payload)
            metadata.append(
                {
                    "path": relative,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        _validate_production_selection(
            {str(item["path"]) for item in metadata},
            file_count=len(metadata),
            total_bytes=total,
        )
        return _metadata_hash(metadata)
    except BioPipeError:
        raise
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.DEPLOYMENT_FAILED,
            "The frozen production snapshot could not be validated.",
            remediation=["Regenerate, validate, test, and preflight the project before retrying."],
        ) from exc


def _read_production_files(root: Path) -> tuple[DeploymentFile, ...]:
    selected: list[DeploymentFile] = []
    total = 0
    candidates = sorted(path for path in root.rglob("*") if path.is_file())
    for candidate in candidates:
        relative = candidate.relative_to(root).as_posix()
        if not _is_production_file(relative):
            continue
        payload = _read_regular_file(candidate)
        if len(payload) > _MAX_FILE_BYTES:
            raise ValueError("deployment file exceeds its size limit")
        total += len(payload)
        selected.append(
            DeploymentFile(
                path=relative,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                content=payload,
            )
        )
    actual = {item.path for item in selected}
    _validate_production_selection(actual, file_count=len(selected), total_bytes=total)
    return tuple(selected)


def _validate_production_selection(
    paths: set[str],
    *,
    file_count: int,
    total_bytes: int,
) -> None:
    if (
        not paths >= _REQUIRED_PRODUCTION_FILES
        or file_count > _MAX_FILES
        or total_bytes > _MAX_BUNDLE_BYTES
    ):
        raise ValueError("deployment bundle is incomplete or exceeds its limits")
    if any(_looks_like_raw_data(path) for path in paths):
        raise ValueError("raw biological data is forbidden in deployment bundles")


def _is_production_file(relative: str) -> bool:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        return False
    if relative in _FIXED_FILES:
        return True
    return len(path.parts) >= 2 and path.parts[0] == "modules" and path.suffix == ".nf"


def _looks_like_raw_data(relative: str) -> bool:
    lowered = relative.casefold()
    return lowered.endswith(
        (
            ".fastq",
            ".fastq.gz",
            ".fq",
            ".fq.gz",
            ".bam",
            ".cram",
            ".sam",
            ".vcf",
            ".vcf.gz",
            ".bcl",
        )
    )


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
            raise ValueError("deployment source is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = _MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_FILE_BYTES:
            raise ValueError("deployment source exceeds its size limit")
        return payload
    finally:
        os.close(descriptor)


def _bundle_hash(files: tuple[DeploymentFile, ...]) -> str:
    metadata: list[dict[str, str | int]] = [
        {"path": item.path, "sha256": item.sha256, "size": item.size} for item in files
    ]
    return _metadata_hash(metadata)


def _metadata_hash(metadata: list[dict[str, str | int]]) -> str:
    canonical = json.dumps(
        sorted(metadata, key=lambda item: str(item["path"])),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "DeploymentBundle",
    "DeploymentFile",
    "build_deployment_bundle",
    "hash_frozen_deployment_snapshot",
]
