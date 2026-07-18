from __future__ import annotations

import errno
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACCEPTANCE_SCRIPT = REPOSITORY_ROOT / "scripts" / "real_host_acceptance.sh"
APPROVAL_PHRASE = "APPROVE-ANONYMOUS-SYNTHETIC-RUN"
PRIVATE_SENTINEL = "patient-SAMPLE-ALPHA__private-host.internal__never-export"
PRIVATE_SECRET = "approval-hmac-private-value-never-export"
FIXED_CONSOLE_LINE = re.compile(
    r"^(?:PHASE [0-9]{2} "
    r"(?:START|PASS|FAIL|INTERRUPTED|AWAITING_APPROVAL)|"
    r"STATUS (?:PREPARED|COMPLETE|FAILED|INVALID_ARGUMENTS))$"
)


@dataclass(frozen=True)
class ScriptHarness:
    root: Path
    fake_bin: Path
    environment: dict[str, str]
    record: Path
    override: Path
    approval_key: Path
    candidate_evidence: Path
    bioprobe: Path
    bioexec: Path
    multiqc_report: Path
    multiqc_data: Path
    command_log: Path
    ssh_log: Path

    def prepare_arguments(self) -> list[str]:
        return [
            "prepare",
            "--record-dir",
            str(self.record),
            "--probe-alias",
            "acceptance-probe",
            "--executor-alias",
            "acceptance-exec",
            "--allowed-root",
            "/srv/biopipe/read",
            "--dataset-root",
            "/srv/biopipe/read/anonymous-paired-fastq",
            "--overrides",
            str(self.override),
            "--deploy-root",
            "/srv/biopipe/deployments",
            "--work-root",
            "/srv/biopipe/work",
            "--output-root",
            str(self.root / "remote-output"),
            "--cache-root",
            "/srv/biopipe/container-cache",
            "--container-engine",
            "docker",
            "--approval-key-id",
            "acceptance-controller-01",
            "--approval-key-file",
            str(self.approval_key),
        ]

    def execute_arguments(self) -> list[str]:
        return [
            "execute",
            "--record-dir",
            str(self.record),
            "--executor-alias",
            "acceptance-exec",
            "--actor",
            "acceptance-operator",
            "--candidate-evidence",
            str(self.candidate_evidence),
            "--multiqc-report",
            str(self.multiqc_report),
            "--multiqc-data",
            str(self.multiqc_data),
            "--bioprobe",
            str(self.bioprobe),
            "--bioexec",
            str(self.bioexec),
        ]


@pytest.fixture
def script_harness(tmp_path: Path) -> ScriptHarness:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(mode=0o700)
    command_log = tmp_path / "private-command-log.jsonl"
    ssh_log = tmp_path / "private-ssh-log.jsonl"
    result_root = tmp_path / "remote-output" / "anonymous-fastq-qc" / "multiqc"
    multiqc_report = result_root / "multiqc_report.html"
    multiqc_data = result_root / "multiqc_data" / "multiqc_data.json"

    _write_executable(fake_bin / "biopipe", _fake_biopipe_program())
    _write_executable(fake_bin / "ssh", _fake_ssh_program())
    _write_executable(fake_bin / "python", _fake_python_program())

    override = tmp_path / "anonymous-overrides.yaml"
    override.write_text(
        textwrap.dedent(
            """\
            override_version: "1.0"
            reason: Anonymous synthetic release acceptance reviewed.
            approved_by: acceptance-operator
            """
        ),
        encoding="utf-8",
    )
    approval_key = tmp_path / "acceptance.hex"
    approval_key.write_text("01" * 32 + "\n", encoding="ascii")
    approval_key.chmod(0o600)
    candidate_evidence = tmp_path / "candidate-evidence"
    candidate_evidence.mkdir(mode=0o700)
    bioprobe = tmp_path / "bioprobe.pyz"
    bioexec = tmp_path / "bioexec.pyz"
    bioprobe.write_bytes(b"mock reviewed probe zipapp\n")
    bioexec.write_bytes(b"mock reviewed executor zipapp\n")

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "MOCK_COMMAND_LOG": str(command_log),
            "MOCK_SSH_LOG": str(ssh_log),
            "MOCK_MULTIQC_REPORT": str(multiqc_report),
            "MOCK_MULTIQC_DATA": str(multiqc_data),
            "MOCK_PRIVATE_SENTINEL": PRIVATE_SENTINEL,
            "MOCK_PRIVATE_SECRET": PRIVATE_SECRET,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return ScriptHarness(
        root=tmp_path,
        fake_bin=fake_bin,
        environment=environment,
        record=tmp_path / "acceptance-record",
        override=override,
        approval_key=approval_key,
        candidate_evidence=candidate_evidence,
        bioprobe=bioprobe,
        bioexec=bioexec,
        multiqc_report=multiqc_report,
        multiqc_data=multiqc_data,
        command_log=command_log,
        ssh_log=ssh_log,
    )


def test_syntax_and_help_are_bounded_and_do_not_expose_ambient_values(
    script_harness: ScriptHarness,
) -> None:
    environment = {
        **script_harness.environment,
        "SAMPLE_NAME": PRIVATE_SENTINEL,
        "BIOPIPE_APPROVAL_HMAC_KEY": PRIVATE_SECRET,
    }
    syntax = subprocess.run(
        ["/bin/bash", "-n", str(ACCEPTANCE_SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )
    help_result = subprocess.run(
        ["/bin/bash", str(ACCEPTANCE_SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )

    assert syntax.returncode == 0
    assert syntax.stdout == syntax.stderr == ""
    assert help_result.returncode == 0
    assert "real_host_acceptance.sh prepare [OPTIONS]" in help_result.stdout
    assert "real_host_acceptance.sh execute [OPTIONS]" in help_result.stdout
    assert help_result.stderr == ""
    _assert_private_values_absent(syntax.stdout + syntax.stderr)
    _assert_private_values_absent(help_result.stdout + help_result.stderr)
    assert not script_harness.command_log.exists()
    assert not script_harness.ssh_log.exists()


def test_mocked_prepare_and_execute_use_the_fixed_safe_chain(
    script_harness: ScriptHarness,
) -> None:
    prepare = _run_script(
        script_harness.prepare_arguments(),
        environment=script_harness.environment,
    )
    assert prepare.returncode == 0
    assert "STATUS PREPARED" in prepare.stdout
    assert prepare.stderr == ""
    _assert_fixed_console(prepare.stdout)
    _assert_private_values_absent(prepare.stdout + prepare.stderr)

    assert not script_harness.multiqc_report.exists()
    assert not script_harness.multiqc_data.exists()
    script_harness.multiqc_report.parent.mkdir(parents=True)
    script_harness.multiqc_report.write_text("pre-existing output\n", encoding="utf-8")
    rejected = _run_script(
        script_harness.execute_arguments(),
        environment=script_harness.environment,
    )
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert rejected.stderr == "STATUS INVALID_ARGUMENTS\n"
    script_harness.multiqc_report.unlink()

    assert not script_harness.multiqc_report.exists()
    assert not script_harness.multiqc_data.exists()
    execute = _run_script_in_pty(
        script_harness.execute_arguments(),
        environment=script_harness.environment,
    )
    assert execute.returncode == 0
    assert "STATUS COMPLETE" in execute.stdout
    _assert_fixed_console(execute.stdout)
    _assert_private_values_absent(execute.stdout)
    assert APPROVAL_PHRASE not in execute.stdout

    assert script_harness.multiqc_report.is_file()
    assert script_harness.multiqc_report.stat().st_size > 0
    assert not script_harness.multiqc_report.is_symlink()
    assert script_harness.multiqc_data.is_file()
    assert script_harness.multiqc_data.stat().st_size > 0
    assert not script_harness.multiqc_data.is_symlink()
    assert (
        script_harness.record / "private" / "approval-denial-preview.stdout"
    ).read_bytes() == b""
    assert (script_harness.record / "private" / "approval-denial.stdout").read_bytes() == b""

    _assert_fixed_command_order(_read_json_lines(script_harness.command_log))
    _assert_strict_force_command_checks(_read_json_lines(script_harness.ssh_log))


def test_failure_keeps_private_diagnostics_and_has_a_fixed_console(
    script_harness: ScriptHarness,
) -> None:
    environment = {**script_harness.environment, "MOCK_FAIL_COMMAND": "inspect"}
    result = _run_script(script_harness.prepare_arguments(), environment=environment)

    assert result.returncode == 2
    assert "PHASE 10 FAIL" in result.stderr
    assert result.stderr.endswith("STATUS FAILED\n")
    _assert_fixed_console(result.stdout + result.stderr)
    _assert_private_values_absent(result.stdout + result.stderr)
    assert script_harness.record.is_dir()
    assert (script_harness.record / "controller" / "project").is_dir()
    diagnostic = script_harness.record / "logs" / "10-inspect.stderr"
    assert diagnostic.is_file()
    assert PRIVATE_SENTINEL in diagnostic.read_text(encoding="utf-8")
    assert PRIVATE_SECRET in diagnostic.read_text(encoding="utf-8")
    assert (script_harness.record / "logs" / "09-inspect-preview.stdout").is_file()


def test_execute_rejects_endpoint_and_output_binding_mismatches(
    script_harness: ScriptHarness,
) -> None:
    prepare = _run_script(
        script_harness.prepare_arguments(),
        environment=script_harness.environment,
    )
    assert prepare.returncode == 0
    profile_path = (
        script_harness.record
        / "controller"
        / "execution-profiles"
        / "anonymous-real-host-local.json"
    )
    original_profile = profile_path.read_bytes()
    profile = json.loads(original_profile)
    profile["ssh_alias"] = "different-endpoint"
    profile_path.write_text(json.dumps(profile) + "\n", encoding="utf-8")

    endpoint_mismatch = _run_script(
        script_harness.execute_arguments(),
        environment=script_harness.environment,
    )
    assert endpoint_mismatch.returncode == 2
    assert endpoint_mismatch.stdout == ""
    assert endpoint_mismatch.stderr == "STATUS INVALID_ARGUMENTS\n"

    profile_path.write_bytes(original_profile)
    wrong_output_arguments = script_harness.execute_arguments()
    report_index = wrong_output_arguments.index("--multiqc-report") + 1
    wrong_output_arguments[report_index] = str(script_harness.root / "unbound-multiqc.html")
    output_mismatch = _run_script(
        wrong_output_arguments,
        environment=script_harness.environment,
    )
    assert output_mismatch.returncode == 2
    assert output_mismatch.stdout == ""
    assert output_mismatch.stderr == "STATUS INVALID_ARGUMENTS\n"


def test_execute_rejects_symlinked_fixed_record_directory(
    script_harness: ScriptHarness,
) -> None:
    prepare = _run_script(
        script_harness.prepare_arguments(),
        environment=script_harness.environment,
    )
    assert prepare.returncode == 0
    logs = script_harness.record / "logs"
    retained_logs = script_harness.record / "retained-logs"
    logs.rename(retained_logs)
    logs.symlink_to(retained_logs, target_is_directory=True)

    execute = _run_script(
        script_harness.execute_arguments(),
        environment=script_harness.environment,
    )

    assert execute.returncode == 2
    assert execute.stdout == ""
    assert execute.stderr == "STATUS INVALID_ARGUMENTS\n"
    assert logs.is_symlink()
    assert retained_logs.is_dir()


def test_terminal_symlink_output_is_rejected_and_record_is_retained(
    script_harness: ScriptHarness,
) -> None:
    prepare = _run_script(
        script_harness.prepare_arguments(),
        environment=script_harness.environment,
    )
    assert prepare.returncode == 0
    environment = {**script_harness.environment, "MOCK_MULTIQC_KIND": "symlink"}

    assert not script_harness.multiqc_report.exists()
    assert not script_harness.multiqc_data.exists()
    execute = _run_script_in_pty(
        script_harness.execute_arguments(),
        environment=environment,
    )

    assert execute.returncode != 0
    assert "PHASE 46 FAIL" in execute.stdout
    assert "STATUS FAILED" in execute.stdout
    _assert_fixed_console(execute.stdout)
    _assert_private_values_absent(execute.stdout)
    assert script_harness.multiqc_report.is_symlink()
    assert script_harness.record.is_dir()
    assert (script_harness.record / "private" / "audit-after-denial.jsonl").is_file()
    assert not (script_harness.record / "evidence").exists()


def _write_executable(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o700)


def _fake_biopipe_program() -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        from __future__ import annotations

        import json
        import os
        import sys
        from pathlib import Path

        args = sys.argv[1:]
        with Path(os.environ["MOCK_COMMAND_LOG"]).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(args, separators=(",", ":")) + "\\n")

        def option(name: str) -> str:
            return args[args.index(name) + 1]

        def emit(value: dict[str, object]) -> None:
            print(json.dumps(value, separators=(",", ":"), sort_keys=True))

        dry_run = "--dry-run" in args
        command = args[0]
        subcommand = args[1] if len(args) > 1 else ""
        if dry_run:
            if (
                command == "run"
                and "--approve-real-data" not in args
                and "--status" not in args
                and "--abandon-pending" not in args
            ):
                print(
                    json.dumps(
                        {{
                            "error": {{
                                "code": "APPROVAL_REQUIRED",
                                "context": {{}},
                                "message": "blocked",
                                "remediation": [],
                                "severity": "blocking",
                            }}
                        }},
                        separators=(",", ":"),
                    ),
                    file=sys.stderr,
                )
                raise SystemExit(2)
            emit({{"status": "preview"}})
            raise SystemExit(0)

        if command == "source" and subcommand == "add":
            Path(os.environ["BIOPIPE_CONFIG_DIR"]).mkdir(parents=True, exist_ok=True)
            emit({{"status": "added"}})
        elif command == "inspect":
            if os.environ.get("MOCK_FAIL_COMMAND") == "inspect":
                print(
                    os.environ["MOCK_PRIVATE_SENTINEL"],
                    os.environ["MOCK_PRIVATE_SECRET"],
                    file=sys.stderr,
                )
                raise SystemExit(2)
            output = Path(option("--output"))
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("{{}}\\n", encoding="utf-8")
            emit({{"status": "inspected"}})
        elif command == "manifest" and subcommand == "apply-overrides":
            output = Path(option("--output-dir"))
            output.mkdir(parents=True, exist_ok=True)
            (output / "dataset.manifest.resolved.json").write_text("{{}}\\n", encoding="utf-8")
            emit({{"status": "resolved"}})
        elif command == "plan":
            output = Path(option("--output"))
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("{{}}\\n", encoding="utf-8")
            (output.parent / "software.lock.yaml").write_text("{{}}\\n", encoding="utf-8")
            emit({{"status": "planned"}})
        elif command == "generate":
            output = Path(option("--output"))
            (output / "audit").mkdir(parents=True, exist_ok=True)
            (output / "reports").mkdir(parents=True, exist_ok=True)
            (output / "audit" / "events.jsonl").write_text(
                '{{"event":"generated"}}\\n', encoding="utf-8"
            )
            emit({{"status": "generated"}})
        elif command in {{"validate", "test"}}:
            project = Path(args[1])
            reports = project / "reports"
            reports.mkdir(parents=True, exist_ok=True)
            (reports / f"{{command}}.json").write_text("{{}}\\n", encoding="utf-8")
            emit({{"status": "passed"}})
        elif command == "execution-profile" and subcommand == "create":
            output = Path(option("--output-dir"))
            output.mkdir(parents=True, exist_ok=True)
            (output / f"{{args[2]}}.json").write_text(
                json.dumps(
                    {{
                        "profile_id": args[2],
                        "ssh_alias": option("--ssh-alias"),
                        "allowed_roots": {{"output": [option("--output-root")]}},
                    }},
                    separators=(",", ":"),
                )
                + "\\n",
                encoding="utf-8",
            )
            emit({{"status": "created"}})
        elif command == "preflight":
            project = Path(args[1])
            (project / "reports" / "preflight.json").write_text("{{}}\\n", encoding="utf-8")
            with (project / "audit" / "events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write('{{"event":"preflight"}}\\n')
            emit({{"status": "passed"}})
        elif command == "run":
            project = Path(args[1])
            run_id = "run-0123456789abcdef0123456789abcdef"
            if "--status" in args:
                (project / "reports" / "status.json").write_text("{{}}\\n", encoding="utf-8")
                with (project / "audit" / "events.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write('{{"event":"completed"}}\\n')
                report = Path(os.environ["MOCK_MULTIQC_REPORT"])
                data = Path(os.environ["MOCK_MULTIQC_DATA"])
                report.parent.mkdir(parents=True, exist_ok=True)
                data.parent.mkdir(parents=True, exist_ok=True)
                if os.environ.get("MOCK_MULTIQC_KIND") == "symlink":
                    target = report.parent / "unexpected-report-target.html"
                    target.write_text("<!doctype html><html></html>\\n", encoding="utf-8")
                    report.symlink_to(target)
                else:
                    report.write_text("<!doctype html><html></html>\\n", encoding="utf-8")
                data.write_text('{{"mock":true}}\\n', encoding="utf-8")
                emit({{"run_id": run_id, "status": "succeeded"}})
            elif "--approve-real-data" in args:
                (project / "reports" / "run.json").write_text("{{}}\\n", encoding="utf-8")
                with (project / "audit" / "events.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write('{{"event":"submitted"}}\\n')
                emit({{"run_id": run_id, "status": "submitted"}})
            else:
                print(
                    json.dumps(
                        {{
                            "error": {{
                                "code": "APPROVAL_REQUIRED",
                                "context": {{}},
                                "message": "blocked",
                                "remediation": [],
                                "severity": "blocking",
                            }}
                        }},
                        separators=(",", ":"),
                    ),
                    file=sys.stderr,
                )
                raise SystemExit(2)
        else:
            emit({{"status": "ok"}})
        """
    )


def _fake_ssh_program() -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        from __future__ import annotations

        import json
        import os
        import sys
        from pathlib import Path

        with Path(os.environ["MOCK_SSH_LOG"]).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(sys.argv[1:], separators=(",", ":")) + "\\n")
        request = sys.stdin.readline()
        if not request.endswith("\\n"):
            raise SystemExit(2)
        sys.stdout.write(request)
        """
    )


def _fake_python_program() -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        from __future__ import annotations

        import os
        import sys
        from pathlib import Path

        args = sys.argv[1:]
        if args and args[0].endswith("/scripts/collect_real_host_evidence.py"):
            if len(args) > 1 and args[1] == "create":
                output = Path(args[args.index("--output") + 1])
                output.mkdir(parents=True)
                (output / "real-host-acceptance.json").write_text(
                    '{{"status":"mocked"}}\\n', encoding="utf-8"
                )
            print('{{"status":"mocked"}}')
            raise SystemExit(0)
        os.execv(sys.executable, [sys.executable, *args])
        """
    )


def _run_script(
    arguments: list[str],
    *,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", str(ACCEPTANCE_SCRIPT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )


def _run_script_in_pty(
    arguments: list[str],
    *,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    child_pid, master = pty.fork()
    if child_pid == 0:
        os.execve(
            "/bin/bash",
            ["/bin/bash", str(ACCEPTANCE_SCRIPT), *arguments],
            environment,
        )
        raise AssertionError("execve returned")

    output = bytearray()
    deadline = time.monotonic() + 10
    approval_sent = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.kill(child_pid, signal.SIGKILL)
                raise AssertionError("acceptance wrapper exceeded the test timeout")
            ready, _, _ = select.select([master], [], [], remaining)
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output.extend(chunk)
            if not approval_sent and b"PHASE 41 AWAITING_APPROVAL" in output:
                approval_deadline = time.monotonic() + 1
                while termios.tcgetattr(master)[3] & termios.ECHO:
                    if time.monotonic() >= approval_deadline:
                        raise AssertionError("approval prompt did not disable terminal echo")
                    time.sleep(0.001)
                os.write(master, (APPROVAL_PHRASE + "\n").encode("ascii"))
                approval_sent = True
    finally:
        os.close(master)
    _, wait_status = os.waitpid(child_pid, 0)
    return subprocess.CompletedProcess(
        args=[str(ACCEPTANCE_SCRIPT), *arguments],
        returncode=os.waitstatus_to_exitcode(wait_status),
        stdout=output.decode("utf-8", errors="strict").replace("\r", ""),
        stderr="",
    )


def _read_json_lines(path: Path) -> list[list[str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_fixed_console(output: str) -> None:
    lines = [line for line in output.replace("\r", "").splitlines() if line]
    assert lines
    assert all(FIXED_CONSOLE_LINE.fullmatch(line) for line in lines), lines


def _assert_private_values_absent(output: str) -> None:
    assert PRIVATE_SENTINEL not in output
    assert PRIVATE_SECRET not in output


def _command_label(arguments: list[str]) -> str:
    command = arguments[0]
    subcommand = arguments[1] if command in {"source", "manifest", "execution-profile"} else ""
    base = f"{command} {subcommand}".strip()
    if command == "run":
        if "--status" in arguments:
            base = "run status"
        elif "--approve-real-data" in arguments:
            base = "run approved"
        else:
            base = "run denied"
    mode = "preview" if "--dry-run" in arguments else "real"
    return f"{base}:{mode}"


def _assert_fixed_command_order(commands: list[list[str]]) -> None:
    assert [_command_label(arguments) for arguments in commands] == [
        "source add:preview",
        "source add:real",
        "source verify:preview",
        "source verify:real",
        "inspect:preview",
        "inspect:real",
        "manifest show:real",
        "manifest apply-overrides:preview",
        "manifest apply-overrides:real",
        "plan:preview",
        "plan:real",
        "generate:preview",
        "generate:real",
        "validate:preview",
        "validate:real",
        "test:preview",
        "test:real",
        "execution-profile create:preview",
        "execution-profile create:real",
        "preflight:preview",
        "preflight:real",
        "run denied:preview",
        "run denied:real",
        "run approved:preview",
        "run approved:real",
        "run status:preview",
        "run status:real",
    ]


def _assert_strict_force_command_checks(ssh_calls: list[list[str]]) -> None:
    assert len(ssh_calls) == 4
    aliases = ["acceptance-probe", "acceptance-probe", "acceptance-exec", "acceptance-exec"]
    for index, (arguments, alias) in enumerate(zip(ssh_calls, aliases, strict=True)):
        assert arguments[:7] == [
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "--",
            alias,
        ]
        expected_tail = [] if index % 2 == 0 else ["biopipe-forcecommand-self-test"]
        assert arguments[7:] == expected_tail
