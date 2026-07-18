"""CLI access to the frozen machine-readable JSON Schema catalog."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import typer

from biopipe.cli.common import dry_run_result, emit, fail
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.schemas import export_json_schemas, schema_by_name, schema_catalog

schema_app = typer.Typer(
    name="schema",
    help="Inspect or export the frozen MVP JSON Schema v1 catalog.",
    no_args_is_help=True,
)


@schema_app.command("list")
def schema_list(
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """List stable schema names, identifiers, and content digests."""

    try:
        catalog = schema_catalog()
    except BioPipeError as error:
        fail(error)
    emit(catalog, as_json=as_json)


@schema_app.command("show")
def schema_show(
    name: str = typer.Argument(..., help="Model name or NAME.schema.json."),
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Print one complete JSON Schema document."""

    try:
        schema = schema_by_name(name)
    except ValueError:
        fail(
            BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "The requested public schema does not exist.",
                context={"schema": name},
                remediation=["Run `biopipe schema list --json` and choose an exact name."],
            )
        )
    except BioPipeError as error:
        fail(error)
    emit(schema, as_json=as_json)


@schema_app.command("export")
def schema_export(
    output_directory: Path = typer.Option(..., "--output", file_okay=False),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate the request and report files without writing them.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Export deterministic schema v1 files and a catalog manifest."""

    destination = output_directory.expanduser().absolute()
    try:
        catalog = schema_catalog()
    except BioPipeError as error:
        fail(error)
    entries = cast(list[dict[str, str]], catalog["schemas"])
    names = [item["path"] for item in entries]
    names.append("catalog.json")
    paths = [str(destination / name) for name in names]
    if dry_run:
        emit(
            dry_run_result(
                "schema export",
                "would_export",
                would_write=paths,
                details={
                    "output_directory": str(destination),
                    "schema_count": catalog["schema_count"],
                    "schema_version": catalog["schema_version"],
                },
            ),
            as_json=as_json,
        )
        return
    try:
        written = export_json_schemas(destination)
    except BioPipeError as error:
        fail(error)
    emit(
        {
            "catalog_sha256": catalog["catalog_sha256"],
            "files": [str(path) for path in written],
            "schema_version": catalog["schema_version"],
            "status": "exported",
        },
        as_json=as_json,
    )


__all__ = ["schema_app"]
