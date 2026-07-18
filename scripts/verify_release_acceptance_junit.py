#!/usr/bin/env python3
"""Reduce private pytest JUnit output to one fixed, path-free result."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Final

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from biopipe.errors import BioPipeError  # noqa: E402
from biopipe.release_evidence.checksums import read_bounded_regular  # noqa: E402

MAX_JUNIT_BYTES = 1024 * 1024
EXPECTED_TESTS = 3
EXPECTED_TESTCASES: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        (
            "tests.integration.test_m5_controller_executor_e2e",
            "test_controller_executor_local_acceptance_is_gated_audited_and_shell_free",
        ),
        (
            "tests.integration.test_m6_release_acceptance",
            "test_m6_runtime_identity_gate_rejects_unlocked_versions",
        ),
        (
            "tests.integration.test_m6_release_acceptance",
            "test_m6_anonymous_release_acceptance",
        ),
    }
)


def _read_junit(path: Path) -> bytes:
    return read_bounded_regular(
        path,
        role="release_acceptance_junit",
        limit_bytes=MAX_JUNIT_BYTES,
    )


def summarize_junit(path: Path) -> dict[str, object]:
    """Require the fixed acceptance set to pass without failures or skips."""

    try:
        payload = _read_junit(path)
        if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
            raise ValueError("unsafe XML declaration")
        root = ElementTree.fromstring(payload)
    except (BioPipeError, ElementTree.ParseError, ValueError) as exc:
        raise ValueError("INVALID_RELEASE_ACCEPTANCE_JUNIT") from exc
    suites = list(root)
    if root.tag != "testsuites" or len(suites) != 1 or suites[0].tag != "testsuite":
        raise ValueError("INVALID_RELEASE_ACCEPTANCE_JUNIT")
    suite = suites[0]
    counts = {"errors": 0, "failures": 0, "skipped": 0, "tests": 0}
    try:
        for name in counts:
            value = suite.attrib.get(name)
            if value is None or not value.isascii() or not value.isdecimal():
                raise ValueError("invalid count")
            counts[name] = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("INVALID_RELEASE_ACCEPTANCE_JUNIT") from exc
    testcases = list(suite)
    observed = {
        (case.attrib.get("classname"), case.attrib.get("name"))
        for case in testcases
        if case.tag == "testcase"
    }
    if (
        counts != {"errors": 0, "failures": 0, "skipped": 0, "tests": EXPECTED_TESTS}
        or len(testcases) != EXPECTED_TESTS
        or any(case.tag != "testcase" or list(case) for case in testcases)
        or observed != EXPECTED_TESTCASES
    ):
        raise ValueError("RELEASE_ACCEPTANCE_TESTS_NOT_ALL_PASSED")
    return {**counts, "status": "passed"}


def _open_private_directory(directory: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(directory)))
    parts = absolute.parts
    if not parts or not absolute.is_absolute():
        raise OSError("output parent must be absolute")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(parts[0], flags)
    try:
        for component in parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
            raise OSError("output parent is not private")
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_create_only(path: Path, payload: bytes) -> None:
    original = path
    if any(part == ".." for part in original.parts):
        raise OSError("output traversal is not allowed")
    absolute = Path(os.path.abspath(os.fspath(original)))
    if absolute.name in {"", ".", ".."}:
        raise OSError("output filename is invalid")
    parent_descriptor: int | None = None
    descriptor: int | None = None
    temporary_name = f".release-acceptance-result-{secrets.token_hex(16)}.tmp"
    try:
        parent_descriptor = _open_private_directory(absolute.parent)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                raise OSError("output write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(
            temporary_name,
            absolute.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.fsync(parent_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            finally:
                os.close(parent_descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = (
            json.dumps(summarize_junit(args.junit), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if args.output is None:
            sys.stdout.buffer.write(payload)
        else:
            _write_create_only(args.output, payload)
        return 0
    except Exception as exc:
        code = str(exc) if str(exc).isupper() else "RELEASE_ACCEPTANCE_JUNIT_FAILED"
        print(json.dumps({"error": code}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
