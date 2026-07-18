#!/usr/bin/env python3
"""Create or verify local M6.1 release-candidate evidence."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _main() -> int:
    sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
    from biopipe.release_evidence.cli import main

    return main(default_repository=REPOSITORY_ROOT)


if __name__ == "__main__":
    raise SystemExit(_main())
