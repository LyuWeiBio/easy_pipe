"""Typer command tree for implemented and reserved MVP milestones."""

from __future__ import annotations

import json

import typer

from biopipe import __version__
from biopipe.cli.generate import generate_command
from biopipe.cli.inspect import inspect_command
from biopipe.cli.manifest import manifest_app
from biopipe.cli.plan import plan_command
from biopipe.cli.source import source_app
from biopipe.cli.test import test_command
from biopipe.cli.validate import validate_command

app = typer.Typer(
    name="biopipe",
    help="Build auditable, local-first bioinformatics pipelines.",
    no_args_is_help=True,
    invoke_without_command=True,
)
app.add_typer(source_app, name="source")
app.add_typer(manifest_app, name="manifest")
app.command("inspect", help="Inspect Source Host metadata or build an M2 FASTQ manifest.")(
    inspect_command
)
app.command("plan", help="Create the fixed FASTQ-QC planning artifacts.")(plan_command)
app.command("generate", help="Generate a reviewed Nextflow DSL2 project.")(generate_command)
app.command("validate", help="Validate a generated project without using real raw data.")(
    validate_command
)
app.command("test", help="Run stub and small synthetic-data workflow tests.")(test_command)


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


def _register_placeholder(name: str, help_text: str, milestone: str) -> None:
    def command(
        as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
    ) -> None:
        _placeholder(name, as_json)

    command.__name__ = name.replace("-", "_")
    command.__doc__ = f"{help_text} ({milestone} placeholder)."
    app.command(name, help=f"{help_text} [{milestone} placeholder]")(command)


for _name, _help, _milestone in (
    ("preflight", "Check an execution host", "M5"),
    ("run", "Run an explicitly approved project", "M5"),
):
    _register_placeholder(_name, _help, _milestone)


__all__ = ["app"]
