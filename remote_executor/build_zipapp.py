#!/usr/bin/env python3
"""Build byte-reproducible dependency-free executor or compute-worker archives."""

from __future__ import annotations

import argparse
import contextlib
import os
import stat
import time
import zipfile
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = PROJECT_DIR.parent
SOURCE_DIR = PROJECT_DIR / "src" / "bioexec"
LICENSE_FILE = REPOSITORY_ROOT / "LICENSE"
DEFAULT_OUTPUT = PROJECT_DIR / "dist" / "bioexec.pyz"
DEFAULT_WORKER_OUTPUT = PROJECT_DIR / "dist" / "bioexec-compute-preflight"
DEFAULT_EPOCH = 315_532_800
SHEBANG = b"#!/usr/bin/env python3\n"
ARCHIVE_MAINS = {
    "executor": b"from bioexec.main import main\nraise SystemExit(main())\n",
    "compute-preflight": (b"from bioexec.compute_worker import main\nraise SystemExit(main())\n"),
}


def build(
    output: Path,
    source_date_epoch: int,
    artifact: str = "executor",
) -> Path:
    """Build the archive from sorted sources with normalized metadata."""

    if not SOURCE_DIR.is_dir():
        raise RuntimeError(f"missing source package: {SOURCE_DIR}")
    if not LICENSE_FILE.is_file():
        raise RuntimeError(f"missing repository license: {LICENSE_FILE}")
    try:
        archive_main = ARCHIVE_MAINS[artifact]
    except KeyError as exc:
        raise ValueError("artifact must be executor or compute-preflight") from exc
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    timestamp = _zip_timestamp(source_date_epoch)
    sources = sorted(path for path in SOURCE_DIR.rglob("*.py") if "__pycache__" not in path.parts)
    try:
        with temporary.open("wb") as raw_output:
            raw_output.write(SHEBANG)
        with zipfile.ZipFile(temporary, mode="a", compression=zipfile.ZIP_STORED) as archive:
            _write_entry(archive, "__main__.py", archive_main, timestamp)
            _write_entry(archive, "LICENSE", LICENSE_FILE.read_bytes(), timestamp)
            for source in sources:
                archive_name = (Path("bioexec") / source.relative_to(SOURCE_DIR)).as_posix()
                _write_entry(archive, archive_name, source.read_bytes(), timestamp)
        temporary.chmod(0o755)
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
    parser.add_argument(
        "--artifact",
        choices=tuple(ARCHIVE_MAINS),
        default="executor",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH", str(DEFAULT_EPOCH))
    try:
        epoch = int(raw_epoch)
    except ValueError as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from exc
    output = args.output
    if output is None:
        output = DEFAULT_OUTPUT if args.artifact == "executor" else DEFAULT_WORKER_OUTPUT
    print(build(output, epoch, args.artifact))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
