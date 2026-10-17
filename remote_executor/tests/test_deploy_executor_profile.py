"""Deploy-time rejection of bundles that override the agent's executor."""

from __future__ import annotations

import pytest

from bioexec.deployment import (
    DeploymentFile,
    _reject_conflicting_executor_profile,
    _strip_groovy_comments,
)
from bioexec.errors import AgentFailure


def _config_file(path: str, text: str) -> DeploymentFile:
    content = text.encode("utf-8")
    return DeploymentFile(
        path=path,
        parts=tuple(path.split("/")),
        size=len(content),
        sha256="0" * 64,
        content=content,
    )


def _generated_bundle() -> tuple[DeploymentFile, ...]:
    return (
        _config_file("nextflow.config", "includeConfig 'conf/base.config'\n"),
        _config_file("conf/base.config", "// base\n"),
        _config_file("conf/local.config", "process.executor = 'local'\nexecutor.queueSize = 4\n"),
    )


def test_generated_bundle_passes() -> None:
    _reject_conflicting_executor_profile(_generated_bundle())


def test_conflicting_executor_in_local_config_is_rejected() -> None:
    files = (
        _config_file("nextflow.config", ""),
        _config_file("conf/base.config", ""),
        _config_file("conf/local.config", "process.executor = 'slurm'\n"),
    )
    with pytest.raises(AgentFailure) as exc_info:
        _reject_conflicting_executor_profile(files)
    assert exc_info.value.code == "CONFLICTING_EXECUTOR_PROFILE"


def test_conflicting_executor_in_nextflow_config_is_rejected() -> None:
    files = (
        _config_file(
            "nextflow.config",
            'profiles {\n    local {\n        process.executor = "slurm"\n    }\n}\n',
        ),
        _config_file("conf/base.config", ""),
        _config_file("conf/local.config", "process.executor = 'local'\n"),
    )
    with pytest.raises(AgentFailure) as exc_info:
        _reject_conflicting_executor_profile(files)
    assert exc_info.value.code == "CONFLICTING_EXECUTOR_PROFILE"


def test_conflicting_executor_in_base_config_is_rejected() -> None:
    files = (
        _config_file("nextflow.config", ""),
        _config_file("conf/base.config", "process . executor='ignite'\n"),
        _config_file("conf/local.config", ""),
    )
    with pytest.raises(AgentFailure) as exc_info:
        _reject_conflicting_executor_profile(files)
    assert exc_info.value.code == "CONFLICTING_EXECUTOR_PROFILE"


def test_commented_out_executor_does_not_trigger_rejection() -> None:
    files = (
        _config_file(
            "nextflow.config",
            "// process.executor = 'slurm'\n/* process.executor = 'slurm' */\n",
        ),
        _config_file("conf/base.config", ""),
        _config_file("conf/local.config", "process.executor = 'local'\n"),
    )
    _reject_conflicting_executor_profile(files)


def test_non_utf8_config_is_rejected() -> None:
    files = (
        DeploymentFile(
            path="nextflow.config",
            parts=("nextflow.config",),
            size=3,
            sha256="0" * 64,
            content=b"\xff\xfe\x00",
        ),
        _config_file("conf/base.config", ""),
        _config_file("conf/local.config", ""),
    )
    with pytest.raises(AgentFailure) as exc_info:
        _reject_conflicting_executor_profile(files)
    assert exc_info.value.code == "CONFLICTING_EXECUTOR_PROFILE"


def test_strip_groovy_comments_keeps_quoted_slashes() -> None:
    text = "url = 'https://example.com/x' // trailing\nprocess.executor='local'\n"
    stripped = _strip_groovy_comments(text)
    assert "https://example.com/x" in stripped
    assert "trailing" not in stripped
    assert "process.executor='local'" in stripped
