"""Typer command tree for implemented and reserved MVP milestones."""

from __future__ import annotations

import json

import typer

from biopipe import __version__
from biopipe.cli.inspect import inspect_command
from biopipe.cli.source import source_app

app = typer.Typer(
    name="biopipe",
    help="Build auditable, local-first bioinformatics pipelines.",
    no_args_is_help=True,
    invoke_without_command=True,
)
manifest_app = typer.Typer(help="Inspect and resolve dataset manifests.", no_args_is_help=True)
app.add_typer(source_app, name="source")
app.add_typer(manifest_app, name="manifest")
app.command("inspect", help="Inspect Source Host metadata with the read-only M1 probe.")(
    inspect_command
)


def _placeholder(command: str, as_json: bool) -> None:
    message = f"{command} is reserved by the MVP CLI contract and will be implemented later."
    if as_json:
        typer.echo(
            json.dumps({"status": "not_implemented", "command": command, "message": message})
        )
    else:
        typer.echo(message)


@app.callback()
def root(
    version: bool = typer.Option(False, "--version", help="Show the controller version and exit."),
) -> None:
    """Initialize the CLI and handle global options."""

    if version:
        typer.echo(__version__)
        raise typer.Exit()


@manifest_app.command("show")
def manifest_show(as_json: bool = typer.Option(False, "--json")) -> None:
    """Show a manifest summary (M2 placeholder)."""

    _placeholder("manifest show", as_json)


@manifest_app.command("apply-overrides")
def manifest_apply_overrides(as_json: bool = typer.Option(False, "--json")) -> None:
    """Resolve explicit manifest overrides (M2 placeholder)."""

    _placeholder("manifest apply-overrides", as_json)


def _register_placeholder(name: str, help_text: str, milestone: str) -> None:
    def command(
        as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
    ) -> None:
        _placeholder(name, as_json)

    command.__name__ = name.replace("-", "_")
    command.__doc__ = f"{help_text} ({milestone} placeholder)."
    app.command(name, help=f"{help_text} [{milestone} placeholder]")(command)


for _name, _help, _milestone in (
    ("plan", "Create a constrained pipeline specification", "M3"),
    ("generate", "Generate a Nextflow project", "M3"),
    ("validate", "Validate a generated project", "M4"),
    ("test", "Test a generated project", "M4"),
    ("preflight", "Check an execution host", "M5"),
    ("run", "Run an explicitly approved project", "M5"),
):
    _register_placeholder(_name, _help, _milestone)


__all__ = ["app"]
