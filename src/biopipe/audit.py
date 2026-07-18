"""Append-only audit logging for controller events."""

from __future__ import annotations

import json
import os
from pathlib import Path

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import AuditEvent


class AuditWriter:
    """Append one complete JSON event per line without truncating prior history."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, event: AuditEvent) -> None:
        """Append and fsync *event*; existing bytes are never rewritten."""

        payload = (
            json.dumps(
                event.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                remaining = memoryview(payload.encode("utf-8"))
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written == 0:
                        raise OSError("audit append made no progress")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise BioPipeError(
                ErrorCode.AUDIT_WRITE_FAILED,
                "Could not append the audit event.",
                context={"path": str(self.path)},
            ) from exc


__all__ = ["AuditWriter"]
