"""Tests for append-only JSON Lines audit persistence."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from biopipe.audit import AuditWriter
from biopipe.errors import BioPipeError, ErrorCode
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


def test_append_once_is_locked_idempotent_and_rejects_semantic_collision(
    tmp_path: Path,
    audit_event_factory: Callable[[str], AuditEvent],
) -> None:
    audit_path = tmp_path / "events.jsonl"
    event = audit_event_factory("00000000-0000-0000-0000-000000000004")
    writer = AuditWriter(audit_path)

    assert writer.append_once(event) is True
    assert writer.append_once(event.model_copy(update={"timestamp": datetime.now(UTC)})) is False
    with pytest.raises(BioPipeError) as collision:
        writer.append_once(event.model_copy(update={"summary": "Different event semantics."}))

    assert collision.value.code is ErrorCode.AUDIT_WRITE_FAILED
    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 1


def test_append_once_scans_chunked_history_with_bounded_lines(
    tmp_path: Path,
    audit_event_factory: Callable[[str], AuditEvent],
) -> None:
    audit_path = tmp_path / "events.jsonl"
    writer = AuditWriter(audit_path)
    events = [
        audit_event_factory(str(UUID(int=index + 10))).model_copy(
            update={"summary": f"Synthetic event {index}: " + "x" * 70_000}
        )
        for index in range(3)
    ]
    for event in events:
        writer.append(event)

    assert writer.append_once(events[1]) is False
    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 3


def test_concurrent_audit_appends_clamp_timestamps_in_durable_order(
    tmp_path: Path,
    audit_event_factory: Callable[[str], AuditEvent],
) -> None:
    audit_path = tmp_path / "audit" / "events.jsonl"
    audit_path.parent.mkdir()
    baseline = datetime(2026, 1, 1, tzinfo=UTC)
    events = [
        audit_event_factory(str(UUID(int=index + 1))).model_copy(
            update={"timestamp": baseline - timedelta(microseconds=index)}
        )
        for index in range(24)
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(AuditWriter(audit_path).append, events))

    written = [
        AuditEvent.model_validate_json(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(written) == len(events)
    assert [event.timestamp for event in written] == sorted(event.timestamp for event in written)


def test_concurrent_append_once_creates_one_durable_event(
    tmp_path: Path,
    audit_event_factory: Callable[[str], AuditEvent],
) -> None:
    audit_path = tmp_path / "audit" / "events.jsonl"
    event = audit_event_factory("00000000-0000-0000-0000-000000000099")

    with ThreadPoolExecutor(max_workers=8) as pool:
        appended = list(pool.map(AuditWriter(audit_path).append_once, [event] * 24))

    assert appended.count(True) == 1
    assert appended.count(False) == 23
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert AuditEvent.model_validate_json(lines[0]) == event
