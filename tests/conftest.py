"""Shared synthetic fixtures for the M0 contract tests."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from biopipe.models import AuditEvent


@pytest.fixture
def audit_event_factory() -> Callable[[str], AuditEvent]:
    """Build deterministic, non-sensitive audit events."""

    def build(event_id: str) -> AuditEvent:
        return AuditEvent.model_validate(
            {
                "schema_version": "1.0",
                "event_id": event_id,
                "timestamp": "2026-01-01T00:00:00Z",
                "event_type": "TEST_COMPLETED",
                "project_id": "synthetic-project",
                "actor": "pytest",
                "input_hashes": {},
                "output_hashes": {},
                "status": "success",
                "summary": "Synthetic M0 audit event.",
            }
        )

    return build
