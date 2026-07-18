"""Metadata-only dataset inspection command implemented by M1."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from biopipe.cli.common import controller_config_dir, emit, fail
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import write_text_atomic
from biopipe.probe import OpenSSHProbeClient
from biopipe.sources import SourceRegistry


def _split_target(target: str) -> tuple[str, str]:
    source_id, separator, root = target.partition(":")
    if not separator or not source_id or not root:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Inspection target must use SOURCE_ID:/absolute/path syntax.",
            remediation=["Example: hpc01:/data/raw/run42"],
        )
    return source_id, root


def inspect_command(
    target: str = typer.Argument(..., help="SOURCE_ID:/absolute/path"),
    policy: str = typer.Option("metadata-only", "--policy"),
    output: Path | None = typer.Option(None, "--output"),
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Return a bounded read-only tree summary from a Source Host."""

    try:
        if policy not in {"metadata-only", "metadata_only"}:
            raise BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "M1 supports only the metadata-only inspection policy.",
                remediation=["Use --policy metadata-only."],
            )
        source_id, root = _split_target(target)
        base = config_dir.expanduser() if config_dir is not None else controller_config_dir()
        profile = SourceRegistry(base / "sources").get(source_id)
        client = OpenSSHProbeClient(
            max_stdout_bytes=profile.probe.max_response_bytes,
            max_stderr_bytes=profile.probe.stderr_limit_bytes,
        )
        response = client.list_tree(profile, root)
        if output is not None:
            payload = json.dumps(
                response.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            write_text_atomic(payload + "\n", output)
    except BioPipeError as error:
        fail(error)
    emit(response, as_json=as_json)


__all__ = ["inspect_command"]
