"""Adversarial tests for the dormant fixed compute-node bootstrap."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from bioexec.compute_bootstrap import (
    BOOTSTRAP_CONTRACT_VERSION,
    ComputeBootstrapError,
    parse_bootstrap_argv,
)

_IDENTITY_SHA256 = "a" * 64
_BOOTSTRAP_SHA256 = "b" * 64


def _argv() -> list[str]:
    return [
        f"--contract-version={BOOTSTRAP_CONTRACT_VERSION}",
        "--config=/srv/biopipe/config/scheduler.json",
        "--run-id=run-1",
        f"--identity-sha256={_IDENTITY_SHA256}",
        f"--bootstrap-sha256={_BOOTSTRAP_SHA256}",
    ]


def test_bootstrap_arguments_are_exact_ordered_and_hash_bound() -> None:
    parsed = parse_bootstrap_argv(_argv())

    assert parsed.contract_version == "1.0"
    assert parsed.config_path == "/srv/biopipe/config/scheduler.json"
    assert parsed.run_id == "run-1"
    assert parsed.identity_sha256 == _IDENTITY_SHA256
    assert parsed.bootstrap_sha256 == _BOOTSTRAP_SHA256


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "reordered",
        "abbreviated",
        "repeated",
        "wrong_version",
        "unsafe_config",
        "unsafe_run",
        "placeholder_hash",
    ],
)
def test_bootstrap_arguments_reject_every_open_command_surface(mutation: str) -> None:
    value = _argv()
    if mutation == "missing":
        value.pop()
    elif mutation == "extra":
        value.append("--shell=/bin/sh")
    elif mutation == "reordered":
        value[1], value[2] = value[2], value[1]
    elif mutation == "abbreviated":
        value[2] = "--run=run-1"
    elif mutation == "repeated":
        value[4] = value[3]
    elif mutation == "wrong_version":
        value[0] = "--contract-version=2.0"
    elif mutation == "unsafe_config":
        value[1] = "--config=/srv/../tmp/config.json"
    elif mutation == "unsafe_run":
        value[2] = "--run-id=../../run-1"
    else:
        value[3] = f"--identity-sha256={'0' * 64}"

    with pytest.raises(ComputeBootstrapError):
        parse_bootstrap_argv(value)


def test_version_one_import_graph_does_not_load_compute_bootstrap() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "import bioexec.main\n"
        "assert 'bioexec.compute_bootstrap' not in sys.modules\n"
        "assert 'bioexec.scheduler_run' not in sys.modules\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
