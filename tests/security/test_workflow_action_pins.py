"""Static supply-chain policy for external GitHub Actions references."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"

APPROVED_ACTIONS = {
    "actions/checkout": (
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0",
    ),
    "actions/setup-python": (
        "ece7cb06caefa5fff74198d8649806c4678c61a1",
        "v6.3.0",
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
    ),
}

USES_LINE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*(?P<reference>[^\s#]+)"
    r"(?:\s+#\s*(?P<version>v\d+\.\d+\.\d+))?\s*$"
)
PINNED_ACTION = re.compile(
    r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?)"
    r"@(?P<sha>[0-9a-f]{40})$"
)
PINNED_CONTAINER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def _workflow_paths() -> list[Path]:
    return sorted([*WORKFLOW_ROOT.rglob("*.yml"), *WORKFLOW_ROOT.rglob("*.yaml")])


def _semantic_uses(workflow_path: Path) -> list[str]:
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), f"invalid workflow document: {workflow_path}"
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), f"workflow has no jobs mapping: {workflow_path}"
    references: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_reference = job.get("uses")
        if job_reference is not None:
            assert isinstance(job_reference, str), f"job uses must be a string: {workflow_path}"
            references.append(job_reference)
        steps = job.get("steps", [])
        assert isinstance(steps, list), f"job steps must be a list: {workflow_path}"
        for step in steps:
            if not isinstance(step, dict) or "uses" not in step:
                continue
            reference = step["uses"]
            assert isinstance(reference, str), f"step uses must be a string: {workflow_path}"
            references.append(reference)
    return references


def test_external_workflow_actions_are_full_sha_pinned_and_allowlisted() -> None:
    violations: list[str] = []
    observed_actions: set[str] = set()

    for workflow_path in _workflow_paths():
        relative_path = workflow_path.relative_to(REPOSITORY_ROOT)
        canonical_references: list[str] = []
        for line_number, line in enumerate(
            workflow_path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if not re.match(r"^\s*(?:-\s*)?uses\s*:", line):
                continue
            location = f"{relative_path}:{line_number}"
            invocation = USES_LINE.fullmatch(line)
            if invocation is None:
                violations.append(f"{location}: unsupported uses syntax")
                continue

            reference = invocation.group("reference")
            canonical_references.append(reference)
            if reference.startswith("./"):
                continue
            if reference.startswith("docker://"):
                if PINNED_CONTAINER.fullmatch(reference) is None:
                    violations.append(f"{location}: container action is not digest-pinned")
                continue

            pinned = PINNED_ACTION.fullmatch(reference)
            if pinned is None:
                violations.append(f"{location}: external action is not pinned to a full SHA")
                continue

            action = pinned.group("action")
            approved = APPROVED_ACTIONS.get(action)
            if approved is None:
                violations.append(f"{location}: external action is not allowlisted: {action}")
                continue

            observed_actions.add(action)
            expected_sha, expected_version = approved
            if pinned.group("sha") != expected_sha:
                violations.append(f"{location}: {action} does not use its reviewed SHA")
            if invocation.group("version") != expected_version:
                violations.append(
                    f"{location}: {action} must be annotated with # {expected_version}"
                )

        semantic_references = _semantic_uses(workflow_path)
        if Counter(canonical_references) != Counter(semantic_references):
            violations.append(
                f"{relative_path}: every uses reference must use canonical block-style syntax"
            )

    missing_actions = sorted(set(APPROVED_ACTIONS) - observed_actions)
    if missing_actions:
        violations.append(f"allowlisted actions are unused: {', '.join(missing_actions)}")

    assert not violations, "\n" + "\n".join(violations)


def test_checkout_does_not_persist_credentials() -> None:
    checkout_steps: list[tuple[Path, dict[str, object]]] = []

    for workflow_path in _workflow_paths():
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict), f"invalid workflow document: {workflow_path}"
        jobs = workflow.get("jobs")
        assert isinstance(jobs, dict), f"workflow has no jobs mapping: {workflow_path}"
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                reference = step.get("uses")
                if isinstance(reference, str) and reference.startswith("actions/checkout@"):
                    checkout_steps.append((workflow_path, step))

    assert checkout_steps, "no actions/checkout steps found"
    for workflow_path, step in checkout_steps:
        settings = step.get("with")
        assert isinstance(settings, dict), f"checkout has no settings: {workflow_path}"
        assert settings.get("persist-credentials") is False, (
            f"checkout must set persist-credentials: false: {workflow_path}"
        )
