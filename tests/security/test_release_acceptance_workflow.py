"""Static contract for the isolated M6.1 release-acceptance workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release-acceptance.yml"
LINUX_MICROMAMBA_SHA256 = "444efe033b145aff00c0e577c111fcc33c3e1e4051de4a98a85ae452cef1a356"
MACOS_MICROMAMBA_SHA256 = "4651dc08f3ac271e1e3aa7db4bd2a934be2732f94cc6764a4c5710505dbbdd78"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
MACOS_CONTROLLER_TESTS = {
    "tests/unit/test_models.py",
    "tests/unit/test_schemas.py",
    "tests/unit/test_manifests.py",
    "tests/unit/test_m3_planner_registry.py",
    "tests/unit/test_compiler.py",
    "tests/unit/test_m6_dry_run.py",
    "tests/integration/test_source_registry.py",
    "tests/integration/test_m1_cli.py",
    "tests/integration/test_m2_cli.py",
    "tests/integration/test_m3_cli.py",
    "tests/integration/test_m5_cli.py",
}


def _workflow() -> dict[str, Any]:
    value = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _job(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    value = jobs[name]
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in job["steps"] if isinstance(item, dict) and item.get("name") == name]
    assert len(matches) == 1
    return cast(dict[str, Any], matches[0])


def test_release_acceptance_has_only_reviewed_triggers_and_permissions() -> None:
    workflow = _workflow()
    triggers = _triggers(workflow)

    assert set(triggers) == {"workflow_dispatch", "push", "pull_request"}
    push = triggers["push"]
    pull_request = triggers["pull_request"]
    assert push["branches"] == ["main"]
    assert push["tags"] == ["v*-rc*"]
    assert pull_request["branches"] == ["main"]
    assert push["paths"] == pull_request["paths"]
    assert len(push["paths"]) == len(set(push["paths"]))
    required_paths = {
        ".github/workflows/release-acceptance.yml",
        "environments/**",
        "release-evidence/**",
        "remote_executor/**",
        "remote_probe/**",
        "scripts/**",
        "src/biopipe/**",
        "tests/**",
    }
    assert required_paths <= set(push["paths"])
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"linux-release-acceptance", "macos-controller"}


def test_linux_job_uses_exact_lock_for_real_tools_and_sanitized_evidence() -> None:
    workflow = _workflow()
    linux = _job(workflow, "linux-release-acceptance")
    assert linux["runs-on"] == "ubuntu-24.04"
    assert linux["timeout-minutes"] == 45
    assert workflow["env"]["BIOPIPE_REQUIRE_REAL_TOOLS"] == "1"
    assert workflow["env"]["NXF_OFFLINE"] == "true"
    assert workflow["env"]["PYTHONDONTWRITEBYTECODE"] == "1"

    install = _step(linux, "Install reviewed micromamba")
    assert install["env"]["MICROMAMBA_SHA256"] == LINUX_MICROMAMBA_SHA256
    assert "/1.5.6-0/micromamba-linux-64" in install["env"]["MICROMAMBA_URL"]
    assert "sha256sum --check --strict" in install["run"]
    create = _step(linux, "Create exact Linux environment")["run"]
    assert "environments/locks/linux-64.explicit.txt" in create
    assert "--name release-acceptance" in create

    verify = _step(linux, "Verify native lock and runtime identities")["run"]
    assert "env export --explicit" in verify
    assert "verify-export" in verify
    assert "--platform linux-64" in verify
    assert "generate_supply_chain_inventory.py verify" in verify
    assert "Python 3.12.11" in verify

    build = _step(linux, "Build reproducible release artifacts")["run"]
    assert "git --no-replace-objects archive --format=tar HEAD" in build
    assert "python -m build --no-isolation --wheel --sdist" in build
    assert build.count("remote_probe/build_zipapp.py") == 2
    assert build.count("remote_executor/build_zipapp.py") == 2
    assert build.count("cmp ") == 2

    installs = _step(linux, "Verify isolated wheel and sdist installs")["run"]
    assert "python -m venv" in installs
    assert 'smoke_artifact "${wheels[0]}" wheel' in installs
    assert 'smoke_artifact "${sdists[0]}" sdist' in installs
    assert "-m pip check" in installs
    assert "verify_installed_package.py" in installs

    demo = _step(linux, "Run forced real-tool acceptance")["run"]
    assert "BIOPIPE_ACCEPTANCE_RESULT=" in demo
    assert "bash scripts/demo_release_acceptance.sh" in demo
    collect = _step(linux, "Create sanitized acceptance evidence")["run"]
    assert "create_release_acceptance_evidence.py create" in collect
    assert "create_release_acceptance_evidence.py verify" in collect
    assert '"$release_root/wheel-venv/bin/python" -I -c' in collect
    assert "CONTROLLER_VERSION" in collect
    assert 'release_id="${candidate_version}-rc${GITHUB_RUN_NUMBER}"' in collect
    assert 'test "${release_id%-rc*}" = "$candidate_version"' in collect
    assert "release-acceptance.junit.xml" not in collect

    steps = linux["steps"]
    upload_index = next(
        index for index, item in enumerate(steps) if item.get("uses") == UPLOAD_ACTION
    )
    collect_index = next(
        index
        for index, item in enumerate(steps)
        if item.get("name") == "Create sanitized acceptance evidence"
    )
    assert collect_index < upload_index
    upload = cast(dict[str, Any], steps[upload_index])
    assert upload["with"] == {
        "name": "release-acceptance-evidence-${{ github.sha }}",
        "path": (
            "${{ runner.temp }}/easy-pipe-release-acceptance/evidence-parent/release-acceptance"
        ),
        "if-no-files-found": "error",
        "retention-days": 30,
        "compression-level": 6,
        "overwrite": False,
        "include-hidden-files": False,
        "archive": True,
    }


def test_macos_job_is_native_arm64_and_controller_only() -> None:
    workflow = _workflow()
    macos = _job(workflow, "macos-controller")
    assert macos["runs-on"] == "macos-15"
    assert macos["timeout-minutes"] == 35
    guard = _step(macos, "Confirm native arm64 runner")["run"]
    assert 'test "$RUNNER_ARCH" = "ARM64"' in guard
    assert 'test "$(uname -m)" = "arm64"' in guard

    install = _step(macos, "Install reviewed micromamba")
    assert install["env"]["MICROMAMBA_SHA256"] == MACOS_MICROMAMBA_SHA256
    assert "/1.5.6-0/micromamba-osx-arm64" in install["env"]["MICROMAMBA_URL"]
    assert "shasum -a 256" in install["run"]
    create = _step(macos, "Create exact macOS arm64 environment")["run"]
    assert "environments/locks/osx-arm64.explicit.txt" in create
    verify = _step(macos, "Verify native macOS lock")["run"]
    assert "--platform osx-arm64" in verify
    package = _step(macos, "Verify installed controller package and schemas")["run"]
    assert "git --no-replace-objects archive --format=tar HEAD" in package
    assert 'python -m venv "$release_root/package-venv"' in package
    assert '"$package_python" -m pip check' in package
    assert "verify_installed_package.py" in package
    assert 'package-venv/bin/biopipe" version --json' in package
    assert 'package-venv/bin/biopipe" schema list --json' in package

    controller = _step(macos, "Run controller-only compatibility tests")["run"]
    observed_tests = {
        token
        for token in controller.split()
        if token.startswith("tests/") and token.endswith(".py")
    }
    assert observed_tests == MACOS_CONTROLLER_TESTS
    forbidden = (
        "demo_release_acceptance",
        "remote_probe",
        "remote_executor",
        "test_m6_release_acceptance",
        "docker",
        "apptainer",
    )
    assert not any(value in controller.casefold() for value in forbidden)


def test_workflow_has_no_failure_bypass_secrets_or_broad_upload() -> None:
    workflow = _workflow()
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "pull_request_target" not in text
    assert "continue-on-error" not in text
    assert "if: always()" not in text
    assert "secrets." not in text
    assert "${{ runner.temp }}/**" not in text
    assert "path: ." not in text
    for job_name in workflow["jobs"]:
        job = _job(workflow, job_name)
        for step in job["steps"]:
            assert step.get("continue-on-error") is not True
