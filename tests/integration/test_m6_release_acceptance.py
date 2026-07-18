"""Offline M6 acceptance from anonymous source registration through audited execution."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import biopipe.cli.inspect as inspect_cli
import biopipe.cli.source as source_cli
import biopipe.execution.preflight as execution_preflight
import biopipe.execution.runner as execution_runner
from biopipe.cli.app import app
from biopipe.execution.client import ExecutionOperation
from biopipe.execution.models import compute_input_set_hash
from biopipe.execution.signing import canonical_attestation_bytes
from biopipe.manifests import verify_manifest
from biopipe.models import DatasetManifest, SourceProfile
from bioprobe.config import ProbeConfig, load_config
from bioprobe.main import run_stream

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = REPOSITORY_ROOT / "examples" / "demo"
_RUNNER = CliRunner()
_REMOTE_CHECKS = (
    "cache_writable",
    "container",
    "disk_space",
    "host_relationship",
    "output_dir_writable",
    "path_mapping",
    "rawdata_readable",
    "runtime",
    "workdir_writable",
)
_COMMAND_HASH = hashlib.sha256(b"m6-demo-nextflow-command").hexdigest()
_ENVIRONMENT_HASH = hashlib.sha256(b"m6-demo-nextflow-environment").hexdigest()
_REQUIRED_TOOLS = ("java", "nextflow", "nf-test", "fastqc", "fastp", "multiqc")
_LOCKED_RUNTIME_IDENTITIES = {
    "java": (("java", "-version"), "23.0.2"),
    "nextflow": (("nextflow", "-version"), "26.04.6"),
    "nf-test": (("nf-test", "version"), "0.9.5"),
}


@dataclass(slots=True)
class _ProbeProtocol:
    """Replace only SSH transport while retaining the production probe protocol."""

    config: ProbeConfig
    operations: list[str] = field(default_factory=list)

    def __call__(
        self,
        args: Sequence[str],
        *,
        input: str,
        text: bool,
        capture_output: bool,
        timeout: float,
        check: bool,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]:
        request = json.loads(input)
        self.operations.append(str(request["operation"]))
        assert list(args[:2]) == ["ssh", "-T"]
        assert text is True
        assert capture_output is True
        assert timeout > 0
        assert check is False
        assert shell is False
        output = io.StringIO()
        return_code = run_stream(io.BytesIO(input.encode("utf-8")), output, self.config)
        return subprocess.CompletedProcess(list(args), return_code, output.getvalue(), "")


@dataclass(slots=True)
class _TrustedExecutionFixture:
    """Deterministic remote boundary for an offline host/container acceptance run."""

    calls: list[tuple[ExecutionOperation, dict[str, Any]]] = field(default_factory=list)
    work_dir: str = ""
    output_dir: str = ""

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        del request_id
        assert source.source_id == payload["profile_id"]
        assert agent_path.endswith("/bioexec.pyz")
        self.calls.append((operation, payload))
        if operation == "preflight":
            self.work_dir = payload["work_dir"]
            self.output_dir = payload["output_dir"]
            assert payload["network_disabled"] is True
            return {
                "preflight_id": payload["preflight_id"],
                "preflight_token": "t" * 64,
                "status": "passed",
                "checks": [
                    {"name": name, "status": "passed", "code": None, "message": None}
                    for name in _REMOTE_CHECKS
                ],
                "input_count": len(set(payload["execution_paths"])),
                "input_set_hash": compute_input_set_hash(payload["execution_paths"]),
            }
        if operation == "deploy":
            assert all(not item["path"].startswith("tests/") for item in payload["files"])
            assert all(
                not item["path"].endswith((".fastq", ".fastq.gz", ".fq", ".fq.gz"))
                for item in payload["files"]
            )
            return {
                "deployment_id": payload["deployment_id"],
                "bundle_hash": payload["bundle_hash"],
                "file_count": len(payload["files"]),
                "status": "deployed",
            }
        if operation == "submit":
            approval = payload["approval"]
            unsigned_approval = {
                key: value for key, value in approval.items() if key != "signature"
            }
            expected = hmac.new(
                bytes.fromhex("9" * 64),
                canonical_attestation_bytes(
                    operation,
                    {**payload, "approval": unsigned_approval},
                ),
                hashlib.sha256,
            ).hexdigest()
            assert hmac.compare_digest(approval["signature"], expected)
            assert approval["approved"] is True
            return {
                "run_id": payload["run_id"],
                "status": "submitted",
                "remote_work_dir": self.work_dir,
                "result_dir": self.output_dir,
                "command_hash": _COMMAND_HASH,
                "environment_hash": _ENVIRONMENT_HASH,
            }
        if operation == "status":
            return {
                "run_id": payload["run_id"],
                "status": "succeeded",
                "return_code": 0,
                "command_hash": _COMMAND_HASH,
                "environment_hash": _ENVIRONMENT_HASH,
            }
        raise AssertionError(f"unexpected execution operation: {operation}")


def _invoke(arguments: list[str], *, expected: int = 0) -> dict[str, Any]:
    result = _RUNNER.invoke(app, [*arguments, "--json"])
    failure_output = result.output
    if os.environ.get("BIOPIPE_SYNTHETIC_CI_DIAGNOSTICS") == "1":
        diagnostic_start = result.stderr.find("BIOPIPE_SYNTHETIC_DIAGNOSTIC_BEGIN")
        diagnostic_end = result.stderr.find("BIOPIPE_SYNTHETIC_DIAGNOSTIC_END")
        if 0 <= diagnostic_start <= diagnostic_end:
            diagnostic_end += len("BIOPIPE_SYNTHETIC_DIAGNOSTIC_END")
            failure_output = f"{failure_output}\n{result.stderr[diagnostic_start:diagnostic_end]}"
    assert result.exit_code == expected, failure_output
    selected = result.stdout if expected == 0 else result.stderr
    payload = json.loads(selected)
    assert isinstance(payload, dict)
    return payload


def _require_real_tools() -> None:
    missing = [name for name in _REQUIRED_TOOLS if shutil.which(name) is None]
    mismatched = [] if missing else _runtime_identity_mismatches()
    if not missing and not mismatched:
        return
    reasons: list[str] = []
    if missing:
        reasons.append(f"unavailable: {', '.join(missing)}")
    if mismatched:
        reasons.append(f"version mismatch: {', '.join(mismatched)}")
    message = f"locked M6 demo tools are {'; '.join(reasons)}"
    if os.environ.get("BIOPIPE_REQUIRE_REAL_TOOLS") == "1":
        pytest.fail(message)
    pytest.skip(message)


def _runtime_identity_mismatches() -> list[str]:
    mismatched: list[str] = []
    identity_cwd = os.environ.get("BIOPIPE_TOOL_IDENTITY_CWD")
    for name, (command, expected_version) in _LOCKED_RUNTIME_IDENTITIES.items():
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                cwd=identity_cwd,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            mismatched.append(name)
            continue
        observed = f"{completed.stdout}\n{completed.stderr}"
        pattern = re.compile(rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])")
        if completed.returncode != 0 or pattern.search(observed) is None:
            mismatched.append(name)
    return mismatched


def test_m6_runtime_identity_gate_rejects_unlocked_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="version 0.0.0",
            stderr="",
        ),
    )

    assert _runtime_identity_mismatches() == ["java", "nextflow", "nf-test"]


def _prepare_probe(raw_root: Path, configuration: Path) -> _ProbeProtocol:
    configuration.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(raw_root)],
                "limits": {
                    "max_depth": 4,
                    "max_entries": 100,
                    "max_runtime_seconds": 30,
                    "max_request_bytes": 1024 * 1024,
                    "max_response_bytes": 10 * 1024 * 1024,
                    "max_paths": 100,
                    "max_path_bytes": 4096,
                    "max_sample_records_total": 100,
                    "max_content_bytes": 1024 * 1024,
                    "max_input_bytes": 1024 * 1024,
                    "max_fastq_line_bytes": 4096,
                },
                "follow_symlinks": False,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    configuration.chmod(0o600)
    return _ProbeProtocol(load_config(configuration))


def test_m6_anonymous_release_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the complete reviewed MVP path with no network or biological data."""

    _require_real_tools()
    raw_root = tmp_path / "anonymous-raw"
    shutil.copytree(DEMO_ROOT / "input", raw_root)
    for path in raw_root.iterdir():
        path.chmod(0o400)

    probe_protocol = _prepare_probe(raw_root, tmp_path / "bioprobe.config.json")
    from biopipe.probe import OpenSSHProbeClient

    probe_client = OpenSSHProbeClient(runner=probe_protocol)
    monkeypatch.setattr(source_cli, "OpenSSHProbeClient", lambda **_kwargs: probe_client)
    monkeypatch.setattr(inspect_cli, "OpenSSHProbeClient", lambda **_kwargs: probe_client)

    config_dir = tmp_path / "controller-config"
    added = _invoke(
        [
            "source",
            "add",
            "demo-source",
            "--host",
            "offline-demo",
            "--allowed-root",
            str(raw_root),
            "--config-dir",
            str(config_dir),
        ]
    )
    assert added["source_id"] == "demo-source"
    verified = _invoke(["source", "verify", "demo-source", "--config-dir", str(config_dir)])
    assert verified["success"] is True

    scan_dir = tmp_path / "scan"
    manifest_path = scan_dir / "dataset.manifest.json"
    scanned = _invoke(
        [
            "inspect",
            f"demo-source:{raw_root}",
            "--policy",
            "format-summary",
            "--sample-fastq-records",
            "4",
            "--output",
            str(manifest_path),
            "--config-dir",
            str(config_dir),
        ]
    )
    manifest = DatasetManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    assert verify_manifest(manifest)
    assert scanned["classification"]["layout"] == "paired_end"
    assert len(manifest.samples) == 1
    assert [lane.lane for lane in manifest.samples[0].lanes] == ["L001", "L002"]
    assert probe_protocol.operations == [
        "health",
        "list_tree",
        "detect_formats",
        "summarize_fastq",
    ]

    summary = _invoke(["manifest", "show", str(manifest_path)])
    assert summary["lane_count"] == 2
    assert summary["paired_lane_count"] == 2
    resolved_dir = tmp_path / "resolved"
    resolution = _invoke(
        [
            "manifest",
            "apply-overrides",
            str(manifest_path),
            "--overrides",
            str(DEMO_ROOT / "overrides.json"),
            "--output-dir",
            str(resolved_dir),
            "--name",
            "dataset",
        ]
    )
    assert resolution["status"] == "resolved"
    resolved_path = resolved_dir / "dataset.manifest.resolved.json"
    resolved = DatasetManifest.model_validate_json(resolved_path.read_text(encoding="utf-8"))
    assert resolved.samples[0].sample_id == "anonymous_control_001"
    assert [lane.lane for lane in resolved.samples[0].lanes] == ["L001", "L002"]

    remote_root = tmp_path / "execution-host"
    roots = {name: remote_root / name for name in ("deploy", "work", "output", "cache")}
    for root in roots.values():
        root.mkdir(parents=True, mode=0o700)
    work_dir = roots["work"] / "anonymous-demo"
    output_dir = roots["output"] / "anonymous-demo"
    cache_dir = roots["cache"] / "anonymous-demo"
    cache_dir.mkdir(mode=0o700)
    planning_dir = tmp_path / "planning"
    spec_path = planning_dir / "pipeline.spec.yaml"
    planned = _invoke(
        [
            "plan",
            "--manifest",
            str(resolved_path),
            "--output",
            str(spec_path),
            "--project-name",
            "anonymous-demo",
            "--trimming",
            "--minimum-length",
            "10",
            "--source-host",
            "demo-source",
            "--execution-host",
            "demo-source",
            "--execution-root",
            str(raw_root),
            "--work-dir",
            str(work_dir),
            "--results-dir",
            str(output_dir),
            "--container-cache",
            str(cache_dir),
            "--container-engine",
            "docker",
            "--max-cpus",
            "4",
            "--max-memory-gb",
            "8",
        ]
    )
    assert planned["status"] == "planned"
    assert {"fastp_paired_v1", "fastqc_raw_v1", "multiqc_v1"} <= set(planned["components"])

    project = tmp_path / "generated-project"
    generated = _invoke(["generate", "--spec", str(spec_path), "--output", str(project)])
    assert generated["status"] == "generated"
    validation = _invoke(["validate", str(project), "--timeout-seconds", "300"])
    assert validation["status"] == "passed"
    tested = _invoke(["test", str(project), "--profile", "test", "--timeout-seconds", "300"])
    assert tested["status"] == "passed"
    e2e = tested["runs"]["e2e"]
    assert e2e["status"] == "passed"
    assert "multiqc/multiqc_report.html" in e2e["outputs"]
    e2e_checks = {check["name"]: check["status"] for check in e2e["checks"]}
    for check in (
        "native_tool_fastp",
        "native_tool_fastqc",
        "native_tool_multiqc",
        "nextflow_e2e",
        "workflow_outputs",
    ):
        assert e2e_checks[check] == "passed"

    approval_key = tmp_path / "approval.key"
    approval_key.write_text("9" * 64 + "\n", encoding="ascii")
    approval_key.chmod(0o600)
    profile_dir = tmp_path / "execution-profiles"
    profile_created = _invoke(
        [
            "execution-profile",
            "create",
            "demo-local",
            "--source-host",
            "demo-source",
            "--execution-host",
            "demo-source",
            "--ssh-alias",
            "offline-demo",
            "--approval-key-id",
            "controller-1",
            "--approval-key-file",
            str(approval_key),
            "--software-lock",
            str(planning_dir / "software.lock.yaml"),
            "--output-dir",
            str(profile_dir),
            "--deploy-root",
            str(roots["deploy"]),
            "--work-root",
            str(roots["work"]),
            "--output-root",
            str(roots["output"]),
            "--cache-root",
            str(roots["cache"]),
            "--container-engine",
            "docker",
            "--minimum-free-bytes",
            str(1024**3),
        ]
    )
    profile_path = Path(profile_created["profile_path"])

    execution_fixture = _TrustedExecutionFixture()
    monkeypatch.setattr(
        execution_preflight,
        "OpenSSHExecutionClient",
        lambda: execution_fixture,
    )
    monkeypatch.setattr(
        execution_runner,
        "OpenSSHExecutionClient",
        lambda: execution_fixture,
    )
    preflight = _invoke(["preflight", str(project), "--execution-profile", str(profile_path)])
    assert preflight["status"] == "passed"

    calls_before_denial = len(execution_fixture.calls)
    denied = _invoke(
        [
            "run",
            str(project),
            "--execution-profile",
            str(profile_path),
            "--actor",
            "demo-operator",
        ],
        expected=2,
    )
    assert denied["error"]["code"] == "APPROVAL_REQUIRED"
    assert len(execution_fixture.calls) == calls_before_denial

    submitted = _invoke(
        [
            "run",
            str(project),
            "--execution-profile",
            str(profile_path),
            "--actor",
            "demo-operator",
            "--approve-real-data",
        ]
    )
    assert submitted["status"] == "submitted"
    status = _invoke(
        [
            "run",
            str(project),
            "--execution-profile",
            str(profile_path),
            "--status",
            submitted["run_id"],
        ]
    )
    assert status["status"] == "succeeded"
    assert [operation for operation, _payload in execution_fixture.calls] == [
        "preflight",
        "deploy",
        "submit",
        "status",
    ]

    audit_events = [
        json.loads(line)
        for line in (project / "audit" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    event_types = [event["event_type"] for event in audit_events]
    for required in (
        "REAL_DATA_APPROVED",
        "PIPELINE_DEPLOYED",
        "RUN_SUBMISSION_STARTED",
        "RUN_SUBMITTED",
        "RUN_STATUS_QUERIED",
        "RUN_COMPLETED",
    ):
        assert required in event_types
    assert event_types.index("REAL_DATA_APPROVED") < event_types.index("RUN_SUBMITTED")
    assert event_types.index("RUN_SUBMITTED") < event_types.index("RUN_COMPLETED")
    execution_events = {
        "REAL_DATA_APPROVED",
        "PIPELINE_DEPLOYED",
        "RUN_SUBMISSION_STARTED",
        "RUN_SUBMITTED",
        "RUN_STATUS_QUERIED",
        "RUN_COMPLETED",
    }
    assert all(
        event["actor"] == "demo-operator"
        for event in audit_events
        if event["event_type"] in execution_events
    )
