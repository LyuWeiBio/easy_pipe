"""Contracts for the procedure-only M6.2 operations runbooks."""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOCS_ROOT = REPOSITORY_ROOT / "docs"
RUNBOOK_NAMES = (
    "internal-pilot-runbook.md",
    "key-rotation-runbook.md",
    "backup-retention-runbook.md",
    "incident-response-runbook.md",
    "capacity-and-quota-runbook.md",
)
STATUS_MARKER = "> Status: **PROCEDURE_ONLY — UNEXECUTED TEMPLATE**."
CHECKED_BOX = re.compile(r"^\s*-\s*\[[xX]\]", re.MULTILINE)
MARKDOWN_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_runbooks_are_explicit_unexecuted_templates() -> None:
    for name in RUNBOOK_NAMES:
        content = _read(DOCS_ROOT / name)
        assert STATUS_MARKER in content
        assert CHECKED_BOX.search(content) is None
        assert "commit/tag" in content.casefold()
        assert "owner:" in content.casefold()


def test_runbook_relative_links_resolve_inside_repository() -> None:
    for name in RUNBOOK_NAMES:
        document = DOCS_ROOT / name
        for raw_target in MARKDOWN_LINK.findall(_read(document)):
            if raw_target.startswith(("#", "https://", "http://", "mailto:")):
                continue
            target = raw_target.partition("#")[0]
            resolved = (document.parent / target).resolve()
            assert resolved.is_relative_to(REPOSITORY_ROOT.resolve())
            assert resolved.is_file(), f"broken link in {name}: {raw_target}"


def test_readme_and_operations_guide_link_every_runbook() -> None:
    readme = _read(REPOSITORY_ROOT / "README.md")
    operations = _read(DOCS_ROOT / "operations.md")
    for name in RUNBOOK_NAMES:
        assert f"(docs/{name})" in readme
        assert f"({name})" in operations


def test_pilot_evidence_compiler_is_linked_and_cannot_overclaim() -> None:
    evidence = _read(DOCS_ROOT / "internal-pilot-evidence.md")
    readme = _read(REPOSITORY_ROOT / "README.md")
    operations = _read(DOCS_ROOT / "operations.md")
    pilot = _read(DOCS_ROOT / "internal-pilot-runbook.md")
    capacity = _read(DOCS_ROOT / "capacity-and-quota-runbook.md")
    assert "(docs/internal-pilot-evidence.md)" in readme
    for content in (operations, pilot, capacity):
        assert "(internal-pilot-evidence.md)" in content
    for marker in (
        "OPERATOR_RECORDED_UNREVIEWED",
        "PENDING_INDEPENDENT_REVIEW",
        "milestone_decision: BLOCKED",
        "production_authorization: false",
        "does not execute",
        "does not verify",
        "Never commit an executed bundle",
    ):
        assert marker.casefold() in evidence.casefold()
    assert "internal-pilot-review-draft.md" in evidence
    assert "collect_internal_pilot_evidence.py verify" in evidence


def test_internal_pilot_covers_required_cases_and_failure_drills() -> None:
    pilot = _read(DOCS_ROOT / "internal-pilot-runbook.md")
    required_labels = (
        "Plain FASTQ single-end",
        "Gzip paired-end",
        "Paired-end multi-lane",
        "Missing mate",
        "Ambiguous naming",
        "Synthetic execution failure",
        "Host-key mismatch",
        "Source unreachable",
        "Path outside root",
        "Unsafe writable input",
        "Container absent",
        "Existing output",
        "Stale preflight",
        "Approval omitted",
        "Lost submit response",
        "Low disk space",
    )
    for label in required_labels:
        assert label in pilot
    for name in RUNBOOK_NAMES[1:]:
        assert f"({name})" in pilot
    assert "## Internal pilot report template" in pilot
    assert "Next recommendation" in pilot


def test_failure_recovery_codes_match_current_controller_boundaries() -> None:
    pilot = _read(DOCS_ROOT / "internal-pilot-runbook.md")
    troubleshooting = _read(DOCS_ROOT / "troubleshooting.md")
    for content in (pilot, troubleshooting):
        assert "OUTPUT_ALREADY_EXISTS" not in content
        assert "PATH_OUTPUT_CONFLICT" in content
        assert "TARGET_ALREADY_EXISTS" in content
        assert "SSH_TIMEOUT" in content
        assert "status_query_required" in content
    assert "UNTRUSTED_PATH_PERMISSIONS" in pilot
    assert "INSUFFICIENT_SPACE" in pilot
    for name in ("operations.md", "remote-deployment.md"):
        content = " ".join(_read(DOCS_ROOT / name).split())
        assert "never resubmit" in content
        assert "status/retry" not in content


def test_pilot_commands_preserve_execution_profile_path_contracts() -> None:
    pilot = _read(DOCS_ROOT / "internal-pilot-runbook.md")
    assert "--container-cache /srv/biopipe/container-cache/pilot-case-001" in pilot
    assert "--executor local" in pilot
    assert "--container-engine docker" in pilot
    assert "biopipe source verify pilot-source --dry-run --json" in pilot
    assert "--policy format-summary" in pilot
    assert "biopipe validate pilot/case-001/generated --dry-run --json" in pilot
    assert "biopipe test pilot/case-001/generated --profile test --dry-run --json" in pilot


def test_key_examples_are_create_only_and_keep_secrets_outside_worktree() -> None:
    rotation = _read(DOCS_ROOT / "key-rotation-runbook.md")
    deployment = _read(DOCS_ROOT / "remote-deployment.md")
    for content in (rotation, deployment):
        assert "os.O_EXCL" in content
        assert "/secure/biopipe/controller-keys/" in content
        assert "> secrets/" not in content
    assert rotation.count("biopipe execution-profile create pilot-executor-next") == 2
    assert "biopipe execution-profile show pilot-executor-next" in rotation


def test_backup_and_capacity_text_do_not_overclaim_recovery_or_quota() -> None:
    backup = _read(DOCS_ROOT / "backup-retention-runbook.md")
    capacity = _read(DOCS_ROOT / "capacity-and-quota-runbook.md")
    assert "does not promise" in backup
    assert "does not preserve its live process lock" in backup
    assert "not a complete history" in backup
    assert "not a hard cap on total run/host CPU" in capacity
    assert "not a total memory limit" in capacity
    assert "There is no `biopipe pause` command" in capacity


def test_capacity_metrics_are_allowlisted_and_sensitive_fields_forbidden() -> None:
    capacity = _read(DOCS_ROOT / "capacity-and-quota-runbook.md")
    for allowed in (
        "scan file count and duration",
        "manifest sample and lane counts",
        "run state transitions and return code",
        "audit parse/order/integrity status",
    ):
        assert allowed in capacity
    for forbidden in (
        "read names",
        "sample names",
        "keys",
        "tokens",
        "complete stdout/stderr",
    ):
        assert forbidden in capacity
