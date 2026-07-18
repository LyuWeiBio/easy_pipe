"""Shared, side-effect-free CLI presentation and configuration helpers."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import Any, NoReturn

import typer
from pydantic import BaseModel, ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.version import CLI_CONTRACT_VERSION


class ExitCode(IntEnum):
    """Stable controller exit codes for the frozen CLI contract."""

    SUCCESS = 0
    COMMAND_FAILED = 2


def controller_config_dir() -> Path:
    """Return the local controller directory, allowing an explicit test override."""

    configured = os.environ.get("BIOPIPE_CONFIG_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "biopipe"


def emit(value: BaseModel | dict[str, Any] | list[Any], *, as_json: bool) -> None:
    """Emit deterministic JSON or a readable JSON representation."""

    if isinstance(value, BaseModel):
        data: Any = value.model_dump(mode="json")
    else:
        data = value
    indent = None if as_json else 2
    typer.echo(json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=True))


def fail(error: BioPipeError) -> NoReturn:
    """Write a stable error envelope to stderr and exit nonzero."""

    typer.echo(error.to_json(), err=True)
    raise typer.Exit(code=ExitCode.COMMAND_FAILED)


def dry_run_result(
    command: str,
    status: str,
    *,
    would_write: Sequence[str] = (),
    remote_operations: Sequence[str] = (),
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the common proof that a dry run performed no side effect."""

    return {
        "cli_contract_version": CLI_CONTRACT_VERSION,
        "command": command,
        "details": dict(sorted((details or {}).items())),
        "dry_run": True,
        "remote_operations": sorted(set(remote_operations)),
        "side_effects_performed": False,
        "status": status,
        "would_write": sorted(set(would_write)),
    }


def validation_error(error: ValidationError) -> NoReturn:
    """Convert Pydantic details into a stable, non-secret CLI error."""

    fail(
        BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Input did not satisfy the required schema.",
            context={
                "fields": [
                    ".".join(str(part) for part in detail["loc"])
                    for detail in error.errors(include_input=False)
                ]
            },
            remediation=["Review the command arguments and retry."],
        )
    )


__all__ = [
    "ExitCode",
    "controller_config_dir",
    "dry_run_result",
    "emit",
    "fail",
    "validation_error",
]
