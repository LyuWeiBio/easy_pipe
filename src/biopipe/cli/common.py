"""Shared, side-effect-free CLI presentation and configuration helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, NoReturn

import typer
from pydantic import BaseModel, ValidationError

from biopipe.errors import BioPipeError, ErrorCode


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
    raise typer.Exit(code=2)


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


__all__ = ["controller_config_dir", "emit", "fail", "validation_error"]
