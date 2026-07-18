"""Typer command tree for implemented and reserved MVP milestones."""

from __future__ import annotations

import typer

from biopipe import __version__
from biopipe.cli.execution_profile import execution_profile_app
from biopipe.cli.generate import generate_command
from biopipe.cli.inspect import inspect_command
from biopipe.cli.manifest import manifest_app
from biopipe.cli.plan import plan_command
from biopipe.cli.preflight import preflight_command
from biopipe.cli.run import run_command
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
app.add_typer(execution_profile_app, name="execution-profile")
app.command("inspect", help="Inspect Source Host metadata or build an M2 FASTQ manifest.")(
    inspect_command
)
app.command("plan", help="Create the fixed FASTQ-QC planning artifacts.")(plan_command)
app.command("generate", help="Generate a reviewed Nextflow DSL2 project.")(generate_command)
app.command("validate", help="Validate a generated project without using real raw data.")(
    validate_command
)
app.command("test", help="Run stub and small synthetic-data workflow tests.")(test_command)
app.command("preflight", help="Check a fixed remote execution profile without running data.")(
    preflight_command
)
app.command("run", help="Submit an explicitly approved fixed workflow or query its status.")(
    run_command
)


@app.callback()
def root(
    version: bool = typer.Option(False, "--version", help="Show the controller version and exit."),
) -> None:
    """Initialize the CLI and handle global options."""

    if version:
        typer.echo(__version__)
        raise typer.Exit()


__all__ = ["app"]
