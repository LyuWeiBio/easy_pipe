#!/usr/bin/env python3
"""Build a byte-reproducible, dependency-free ``bioprobe.pyz`` archive."""

from __future__ import annotations

import argparse
import contextlib
import os
import stat
import time
import zipfile
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
SOURCE_DIR = PROJECT_DIR / "src" / "bioprobe"
DEFAULT_OUTPUT = PROJECT_DIR / "dist" / "bioprobe.pyz"
DEFAULT_EPOCH = 315_532_800  # 1980-01-01, the earliest portable ZIP timestamp.
SHEBANG = b"#!/usr/bin/env python3\n"
ARCHIVE_MAIN = b"from bioprobe.main import main\nraise SystemExit(main())\n"


def build(output: Path, source_date_epoch: int) -> Path:
    """Build the archive from sorted sources with normalized metadata."""

    if not SOURCE_DIR.is_dir():
        raise RuntimeError(f"missing source package: {SOURCE_DIR}")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    timestamp = _zip_timestamp(source_date_epoch)
    sources = sorted(path for path in SOURCE_DIR.rglob("*.py") if "__pycache__" not in path.parts)
    try:
        with temporary.open("wb") as raw_output:
            raw_output.write(SHEBANG)
        with zipfile.ZipFile(temporary, mode="a", compression=zipfile.ZIP_STORED) as archive:
            _write_entry(archive, "__main__.py", ARCHIVE_MAIN, timestamp)
            for source in sources:
                archive_name = (Path("bioprobe") / source.relative_to(SOURCE_DIR)).as_posix()
                _write_entry(archive, archive_name, source.read_bytes(), timestamp)
        temporary.chmod(
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IXUSR
            | stat.S_IRGRP
            | stat.S_IXGRP
            | stat.S_IROTH
            | stat.S_IXOTH
        )
        os.replace(temporary, output)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
    return output


def _write_entry(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
    timestamp: tuple[int, int, int, int, int, int],
) -> None:
    info = zipfile.ZipInfo(filename=name, date_time=timestamp)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits = 0
    archive.writestr(info, data)


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    normalized = max(DEFAULT_EPOCH, epoch)
    value = time.gmtime(normalized)[:6]
    if value[0] > 2107:
        raise ValueError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    return value


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH", str(DEFAULT_EPOCH))
    try:
        epoch = int(raw_epoch)
    except ValueError as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from exc
    result = build(args.output, epoch)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
