"""Subprocess coverage for the private pilot-record authoring CLI."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = REPOSITORY_ROOT / "scripts" / "collect_internal_pilot_evidence.py"
PRIVATE_SENTINEL = "private-approval-material-never-export"


def _run(arguments: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(COLLECTOR), *arguments],
        cwd=cwd,
        env={
            "PATH": "",
            "PYTHONPATH": "",
            "PYTHONDONTWRITEBYTECODE": "1",
            "BIOPIPE_APPROVAL_HMAC_KEY": PRIVATE_SENTINEL,
            "SSH_AUTH_SOCK": f"/private/{PRIVATE_SENTINEL}",
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_init_and_validate_record_cli_are_offline_blocked_and_create_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "case"
    root.mkdir(mode=0o700)
    repository = root / "empty-non-git-repository"
    repository.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    record = private / "pilot-record.json"
    identity = [
        "--repository",
        str(repository),
        "--output",
        str(record),
        "--pilot-id",
        "pilot-20260719-001",
        "--environment-id",
        "env-001",
        "--recorded-at",
        "2026-07-19T08:00:00Z",
        "--release-id",
        "0.1.0-rc1",
        "--source-git-commit",
        "a" * 40,
        "--candidate-manifest-sha256",
        "b" * 64,
        "--release-acceptance-manifest-sha256",
        "c" * 64,
        "--real-host-manifest-sha256",
        "d" * 64,
    ]

    initialized = _run(["init-record", *identity], cwd=root)

    assert initialized.returncode == 0, initialized.stderr
    initialized_result = json.loads(initialized.stdout)
    assert initialized_result["status"] == "pilot_record_initialized_unexecuted_blocked"
    assert initialized_result["source_evidence_authentication_status"] == "NOT_PERFORMED"
    assert initialized_result["independent_review_status"] == "NOT_PERFORMED"
    assert initialized_result["milestone_decision"] == "BLOCKED"
    assert initialized_result["production_authorization"] is False
    assert initialized_result["network_accessed"] is False
    assert str(record) not in initialized.stdout
    assert PRIVATE_SENTINEL not in initialized.stdout
    assert PRIVATE_SENTINEL not in initialized.stderr
    assert stat.S_IMODE(record.stat(follow_symlinks=False).st_mode) == 0o600
    original = record.read_bytes()

    validated = _run(
        [
            "validate-record",
            "--repository",
            str(repository),
            "--sanitized-record",
            str(record),
        ],
        cwd=root,
    )

    assert validated.returncode == 0, validated.stderr
    validated_result = json.loads(validated.stdout)
    assert validated_result["status"] == "pilot_record_strict_format_validated_only"
    assert validated_result["milestone_decision"] == "BLOCKED"
    assert validated_result["production_authorization"] is False
    assert validated_result["exact_record_sha256"] == initialized_result["exact_record_sha256"]
    assert record.read_bytes() == original
    assert str(record) not in validated.stdout
    assert PRIVATE_SENTINEL not in validated.stdout
    assert PRIVATE_SENTINEL not in validated.stderr

    repeated = _run(["init-record", *identity], cwd=root)

    assert repeated.returncode == 2
    assert record.read_bytes() == original
    assert str(record) not in repeated.stderr
    assert PRIVATE_SENTINEL not in repeated.stderr
    assert not any(
        path.name.startswith(".pilot-record.json.biopipe-") for path in private.iterdir()
    )
