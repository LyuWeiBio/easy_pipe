"""Frozen MVP release and public-contract versions.

The controller, compiler, and separately deployed probe deliberately publish
independent names even while their first release numbers are aligned.  Keeping
the values here makes drift visible to compatibility tests and to the CLI.
"""

from __future__ import annotations

CONTROLLER_VERSION = "0.1.0"
COMPILER_VERSION = "0.1.0"
PROBE_VERSION = "0.1.0"
REMOTE_EXECUTOR_VERSION = "0.1.0"
REGISTRY_VERSION = "1.0.0"
MVP_SCHEMA_VERSION = "1.0"
CLI_CONTRACT_VERSION = "1.0"

__all__ = [
    "CLI_CONTRACT_VERSION",
    "COMPILER_VERSION",
    "CONTROLLER_VERSION",
    "MVP_SCHEMA_VERSION",
    "PROBE_VERSION",
    "REGISTRY_VERSION",
    "REMOTE_EXECUTOR_VERSION",
]
