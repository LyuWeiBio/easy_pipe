"""Create and inspect immutable local-executor profiles."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, cast

import typer
from pydantic import ValidationError

from biopipe.cli.common import dry_run_result, emit, fail, validation_error
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalSigner,
    ContainerArtifact,
    DiskThreshold,
    ExecutionPathMapping,
    ExecutionProfile,
    LocalExecutionRuntime,
)
from biopipe.execution.profiles import ExecutionProfileRegistry
from biopipe.execution.signing import validate_approval_key
from biopipe.io import read_model
from biopipe.models import SoftwareLock

execution_profile_app = typer.Typer(
    name="execution-profile",
    help="Create-only M5 local-executor profile management.",
    no_args_is_help=True,
)


@execution_profile_app.command("create")
def create_execution_profile(
    profile_id: str = typer.Argument(..., help="Stable execution-profile identifier."),
    source_host: str = typer.Option(..., "--source-host"),
    execution_host: str = typer.Option(..., "--execution-host"),
    ssh_alias: str = typer.Option(..., "--ssh-alias"),
    software_lock_path: Path = typer.Option(..., "--software-lock"),
    output_directory: Path = typer.Option(..., "--output-dir"),
    deploy_roots: list[str] = typer.Option(..., "--deploy-root"),
    work_roots: list[str] = typer.Option(..., "--work-root"),
    output_roots: list[str] = typer.Option(..., "--output-root"),
    cache_roots: list[str] = typer.Option(..., "--cache-root"),
    container_engine: str = typer.Option("apptainer", "--container-engine"),
    sif_paths: list[str] | None = typer.Option(
        None,
        "--sif",
        help="Apptainer mapping NAME=/absolute/image.sif; repeat for every locked tool.",
    ),
    sif_hashes: list[str] | None = typer.Option(
        None,
        "--sif-sha256",
        help="Apptainer mapping NAME=lowercase_sha256; repeat for every locked tool.",
    ),
    path_mappings: list[str] | None = typer.Option(
        None,
        "--path-mapping",
        help="Shared-filesystem mapping SOURCE_PREFIX=EXECUTION_PREFIX.",
    ),
    username: str | None = typer.Option(None, "--username"),
    port: int = typer.Option(22, "--port", min=1, max=65_535),
    bioexec_path: str = typer.Option("~/.local/bin/bioexec.pyz", "--bioexec-path"),
    approval_key_id: str = typer.Option(
        ...,
        "--approval-key-id",
        help="Identifier shared with the remote agent's trusted approval key.",
    ),
    approval_key_file: Path = typer.Option(
        ...,
        "--approval-key-file",
        help="Owner-only local file containing one lowercase 32-byte HMAC key.",
    ),
    minimum_free_bytes: int = typer.Option(
        10 * 1024**3,
        "--minimum-free-bytes",
        min=1024**3,
        max=1024**5,
    ),
    preflight_max_age_seconds: int = typer.Option(
        900,
        "--preflight-max-age-seconds",
        min=60,
        max=86_400,
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate the profile without reading the approval key or writing it.",
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Create one immutable profile from an exact reviewed software lock."""

    try:
        if container_engine not in {"apptainer", "docker"}:
            raise BioPipeError(
                ErrorCode.EXECUTION_PROFILE_INVALID,
                "The M5 container engine must be apptainer or docker.",
            )
        software_lock = read_model(software_lock_path, SoftwareLock)
        sif_path_map = _assignments(sif_paths or [], "sif")
        sif_hash_map = _assignments(sif_hashes or [], "sif-sha256")
        expected_names = set(software_lock.components)
        if container_engine == "apptainer" and (
            set(sif_path_map) != expected_names or set(sif_hash_map) != expected_names
        ):
            raise BioPipeError(
                ErrorCode.EXECUTION_PROFILE_INVALID,
                "Apptainer requires one local path and file hash for every locked tool.",
                context={"required_components": sorted(expected_names)},
            )
        if container_engine == "docker" and (sif_path_map or sif_hash_map):
            raise BioPipeError(
                ErrorCode.EXECUTION_PROFILE_INVALID,
                "Docker profiles must not declare local SIF artifacts.",
            )
        containers = {
            name: ContainerArtifact(
                image=component.image,
                digest=component.digest,
                local_path=sif_path_map.get(name),
                file_sha256=sif_hash_map.get(name),
            )
            for name, component in sorted(software_lock.components.items())
        }
        mappings = tuple(
            ExecutionPathMapping(source_prefix=source, execution_prefix=execution)
            for source, execution in (_mapping(value) for value in (path_mappings or []))
        )
        profile = ExecutionProfile(
            profile_id=profile_id,
            source_host=source_host,
            execution_host=execution_host,
            ssh_alias=ssh_alias,
            username=username,
            port=port,
            bioexec_path=bioexec_path,
            approval_signer=ApprovalSigner(
                key_id=approval_key_id,
                key_file=str(approval_key_file.expanduser().absolute()),
            ),
            allowed_roots=AllowedExecutionRoots(
                deploy=tuple(deploy_roots),
                work=tuple(work_roots),
                output=tuple(output_roots),
                cache=tuple(cache_roots),
            ),
            runtime=LocalExecutionRuntime(
                container_engine=cast(Literal["apptainer", "docker"], container_engine)
            ),
            containers=containers,
            disk_threshold=DiskThreshold(minimum_free_bytes=minimum_free_bytes),
            preflight_max_age_seconds=preflight_max_age_seconds,
            path_mapping=mappings,
        )
        if dry_run:
            profile_path = output_directory.expanduser().absolute() / f"{profile.profile_id}.json"
            emit(
                dry_run_result(
                    "execution-profile create",
                    "would_create",
                    would_write=[str(profile_path)],
                    details={"profile": profile.model_dump(mode="json")},
                ),
                as_json=as_json,
            )
            return
        validate_approval_key(profile)
        path = ExecutionProfileRegistry(output_directory).register(profile)
    except ValidationError as error:
        validation_error(error)
    except BioPipeError as error:
        fail(error)
    emit(
        {
            "status": "created",
            "profile_path": str(path),
            "profile": profile.model_dump(mode="json"),
        },
        as_json=as_json,
    )


@execution_profile_app.command("show")
def show_execution_profile(
    profile_id: str = typer.Argument(...),
    profile_directory: Path = typer.Option(..., "--profile-dir"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Load one immutable profile through the safe registry."""

    try:
        profile = ExecutionProfileRegistry(profile_directory).load(profile_id)
    except BioPipeError as error:
        fail(error)
    emit(profile, as_json=as_json)


def _assignments(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise BioPipeError(
                ErrorCode.EXECUTION_PROFILE_INVALID,
                f"Every {label} value must use NAME=VALUE.",
            )
        name, selected = value.split("=", maxsplit=1)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) or not selected:
            raise BioPipeError(
                ErrorCode.EXECUTION_PROFILE_INVALID,
                f"A {label} assignment is invalid.",
            )
        if name in result:
            raise BioPipeError(
                ErrorCode.EXECUTION_PROFILE_INVALID,
                f"A {label} component was assigned more than once.",
            )
        result[name] = selected
    return result


def _mapping(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise BioPipeError(
            ErrorCode.EXECUTION_PROFILE_INVALID,
            "Path mappings must use SOURCE_PREFIX=EXECUTION_PREFIX.",
        )
    source, execution = value.split("=", maxsplit=1)
    if not source or not execution:
        raise BioPipeError(
            ErrorCode.EXECUTION_PROFILE_INVALID,
            "A path mapping prefix is empty.",
        )
    return source, execution


__all__ = ["execution_profile_app"]
