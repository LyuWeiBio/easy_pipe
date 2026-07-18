"""Tests for append-only JSON Lines audit persistence."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from biopipe.audit import AuditWriter
from biopipe.models import AuditEvent


def test_audit_writer_appends_without_overwriting_history(
    tmp_path: Path,
    audit_event_factory: Callable[[str], AuditEvent],
) -> None:
    audit_path = tmp_path / "audit" / "events.jsonl"
    first_event = audit_event_factory("00000000-0000-0000-0000-000000000001")
    second_event = audit_event_factory("00000000-0000-0000-0000-000000000002")

    AuditWriter(audit_path).append(first_event)
    # Reopen the writer to ensure append-only behavior is a file-level guarantee.
    AuditWriter(audit_path).append(second_event)

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    events = [AuditEvent.model_validate_json(line) for line in lines]

    assert events == [first_event, second_event]
    assert all(line and "\n" not in line for line in lines)


def test_audit_writer_appends_one_complete_json_object_per_line(
    tmp_path: Path,
    audit_event_factory: Callable[[str], AuditEvent],
) -> None:
    audit_path = tmp_path / "events.jsonl"
    event = audit_event_factory("00000000-0000-0000-0000-000000000003")

    AuditWriter(audit_path).append(event)

    content = audit_path.read_text(encoding="utf-8")
    assert content.endswith("\n")
    assert content.count("\n") == 1
    assert AuditEvent.model_validate_json(content) == event
