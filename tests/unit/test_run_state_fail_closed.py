"""Regression tests: run-state reads are fail-closed, never fail-open.

``_read_optional_run_state`` must return ``None`` only when the state file is
genuinely absent.  A present-but-unreadable state file (corrupt JSON, wrong
file type, permission failure) must raise instead of being silently treated
as "no pending submission", otherwise ``_require_no_pending_submission``
could authorize a second real-data submit while one is still pending.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from biopipe.cli.app import app  # noqa: F401  (import first: runner has a cli import cycle)
from biopipe.errors import BioPipeError
from biopipe.execution.runner import _read_optional_run_state, _require_no_pending_submission


def _context(project: Path) -> Any:
    return SimpleNamespace(project=project)


def _write_state(project: Path, payload: bytes) -> Path:
    reports = project / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    target = reports / ".run-state.json"
    target.write_bytes(payload)
    return target


def test_missing_state_file_reads_as_no_state(tmp_path: Path) -> None:
    assert _read_optional_run_state(_context(tmp_path)) is None
    # ... and the pending-submission gate passes when there is no state.
    _require_no_pending_submission(_context(tmp_path))


def test_corrupted_state_file_is_fail_closed(tmp_path: Path) -> None:
    _write_state(tmp_path, b"{invalid json")
    with pytest.raises(BioPipeError):
        _read_optional_run_state(_context(tmp_path))


def test_non_file_state_entry_is_fail_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / ".run-state.json").mkdir()
    with pytest.raises(BioPipeError):
        _read_optional_run_state(_context(tmp_path))


def test_empty_state_file_is_fail_closed(tmp_path: Path) -> None:
    _write_state(tmp_path, b"")
    with pytest.raises(BioPipeError):
        _read_optional_run_state(_context(tmp_path))
