"""Machine-readable release version command."""

from __future__ import annotations

import typer

from biopipe.cli.common import ExitCode, emit, fail
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.registry import RegistryValidationError, load_default_registry
from biopipe.version import (
    CLI_CONTRACT_VERSION,
    COMPILER_VERSION,
    CONTROLLER_VERSION,
    MVP_SCHEMA_VERSION,
    PROBE_VERSION,
    REGISTRY_VERSION,
    REMOTE_EXECUTOR_VERSION,
)


def version_command(
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Show every version needed to assess MVP compatibility."""

    try:
        observed_registry = load_default_registry().version
    except BioPipeError as error:
        fail(error)
    except RegistryValidationError:
        fail(
            BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "The packaged component registry is invalid.",
                remediation=["Restore the reviewed registry before checking versions."],
            )
        )
    emit(
        {
            "cli_contract_version": CLI_CONTRACT_VERSION,
            "compiler_version": COMPILER_VERSION,
            "controller_version": CONTROLLER_VERSION,
            "exit_codes": {
                "command_failed": int(ExitCode.COMMAND_FAILED),
                "success": int(ExitCode.SUCCESS),
            },
            "probe_version": PROBE_VERSION,
            "registry_version": observed_registry,
            "registry_version_expected": REGISTRY_VERSION,
            "remote_executor_version": REMOTE_EXECUTOR_VERSION,
            "schema_version": MVP_SCHEMA_VERSION,
        },
        as_json=as_json,
    )


__all__ = ["version_command"]
