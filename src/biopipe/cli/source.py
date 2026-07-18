"""SourceProfile CLI commands implemented by M1."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from biopipe.cli.common import (
    controller_config_dir,
    dry_run_result,
    emit,
    fail,
    validation_error,
)
from biopipe.errors import BioPipeError
from biopipe.models import SourceProfile
from biopipe.probe import OpenSSHProbeClient
from biopipe.sources import SourceRegistry

source_app = typer.Typer(help="Manage source-host profiles.", no_args_is_help=True)


def _registry(config_dir: Path | None) -> SourceRegistry:
    base = config_dir.expanduser() if config_dir is not None else controller_config_dir()
    return SourceRegistry(base / "sources")


@source_app.command("add")
def source_add(
    source_id: str = typer.Argument(..., help="Local identifier for the Source Host."),
    host: str = typer.Option(..., "--host", help="Alias from the existing OpenSSH config."),
    username: str | None = typer.Option(None, "--username"),
    port: int | None = typer.Option(None, "--port", min=1, max=65_535),
    allowed_root: list[str] = typer.Option(
        ..., "--allowed-root", help="Approved absolute raw-data root; repeat as needed."
    ),
    remote_probe_path: str = typer.Option("~/.local/bin/bioprobe.pyz", "--remote-probe-path"),
    max_runtime_seconds: int = typer.Option(300, min=1, max=3600),
    max_depth: int = typer.Option(6, min=0, max=64),
    max_entries: int = typer.Option(100_000, min=1, max=10_000_000),
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate and show the profile path without registering it.",
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Register a Source Host without storing SSH credentials."""

    try:
        profile = SourceProfile.model_validate(
            {
                "source_id": source_id,
                "ssh_alias": host,
                "username": username,
                "port": port,
                "allowed_roots": allowed_root,
                "probe": {
                    "remote_path": remote_probe_path,
                    "max_runtime_seconds": max_runtime_seconds,
                    "max_depth": max_depth,
                    "max_entries": max_entries,
                    "follow_symlinks": False,
                },
            }
        )
        registry = _registry(config_dir)
        if dry_run:
            emit(
                dry_run_result(
                    "source add",
                    "would_add",
                    would_write=[str(registry.directory / f"{profile.source_id}.json")],
                    details={"source": profile.model_dump(mode="json")},
                ),
                as_json=as_json,
            )
            return
        stored = registry.add(profile)
    except ValidationError as error:
        validation_error(error)
    except BioPipeError as error:
        fail(error)
    emit(stored, as_json=as_json)


@source_app.command("list")
def source_list(
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List registered Source Hosts."""

    try:
        profiles = _registry(config_dir).list()
    except BioPipeError as error:
        fail(error)
    emit([profile.model_dump(mode="json") for profile in profiles], as_json=as_json)


@source_app.command("show")
def source_show(
    source_id: str = typer.Argument(...),
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show one SourceProfile."""

    try:
        profile = _registry(config_dir).get(source_id)
    except BioPipeError as error:
        fail(error)
    emit(profile, as_json=as_json)


@source_app.command("remove")
def source_remove(
    source_id: str = typer.Argument(...),
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Confirm the exact registered source without removing it.",
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Remove only the local SourceProfile; never contact the Source Host."""

    try:
        registry = _registry(config_dir)
        if dry_run:
            selected = registry.get(source_id)
            emit(
                dry_run_result(
                    "source remove",
                    "would_remove",
                    would_write=[str(registry.directory / f"{selected.source_id}.json")],
                    details={"source_id": selected.source_id},
                ),
                as_json=as_json,
            )
            return
        removed = registry.remove(source_id)
    except BioPipeError as error:
        fail(error)
    emit(
        {"status": "removed", "source": removed.model_dump(mode="json")},
        as_json=as_json,
    )


@source_app.command("verify")
def source_verify(
    source_id: str = typer.Argument(...),
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate the registered source without contacting the probe.",
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Send a fixed health request to the registered Remote Probe."""

    try:
        profile = _registry(config_dir).get(source_id)
        if dry_run:
            emit(
                dry_run_result(
                    "source verify",
                    "would_verify",
                    remote_operations=["probe.health"],
                    details={"source_id": profile.source_id},
                ),
                as_json=as_json,
            )
            return
        client = OpenSSHProbeClient(
            max_stdout_bytes=profile.probe.max_response_bytes,
            max_stderr_bytes=profile.probe.stderr_limit_bytes,
        )
        response = client.verify(profile)
    except BioPipeError as error:
        fail(error)
    emit(response, as_json=as_json)


__all__ = ["source_app"]
