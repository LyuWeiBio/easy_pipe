"""Dormant M7 Slurm contract tests; no scheduler process is invoked here."""

from __future__ import annotations

import ast
import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from bioexec.errors import AgentFailure, ReturnCode
from bioexec.protocol import parse_request
from bioexec.slurm import (
    SlurmContractError,
    SlurmHeldJob,
    SlurmJobRef,
    SlurmMappedState,
    SlurmObservation,
    SlurmSchedulerPolicy,
    SlurmSubmitSpec,
    build_sacct_argv,
    build_sbatch_argv,
    build_scheduler_environment,
    build_scontrol_release_argv,
    build_squeue_argv,
    build_squeue_discovery_argv,
    build_squeue_hold_argv,
    canonical_scheduler_policy_bytes,
    map_slurm_observation,
    parse_sacct_output,
    parse_sbatch_parsable_output,
    parse_squeue_discovery_output,
    parse_squeue_hold_output,
    parse_squeue_output,
    reconcile_slurm_observations,
    scheduler_policy_hash,
)

_MARKER = "a" * 64
_OTHER_MARKER = "b" * 64
_SUBMITTED_AT = "2026-07-19T12:34:56"


def _policy_mapping() -> dict[str, object]:
    return {
        "partition": "compute",
        "account": "bioinfo",
        "qos": "normal",
        "time_limit": "08:00:00",
        "cpus_per_task": 8,
        "memory_mib": 16_384,
        "submit_timeout_seconds": 60,
        "status_poll_seconds": 30,
        "max_pending_seconds": 3600,
    }


def _policy() -> SlurmSchedulerPolicy:
    return SlurmSchedulerPolicy.from_mapping(_policy_mapping())


def _submit_spec(**updates: object) -> SlurmSubmitSpec:
    values: dict[str, object] = {
        "policy": _policy(),
        "submission_marker": _MARKER,
        "working_directory": "/srv/biopipe/work/run-1",
        "log_directory": "/srv/biopipe/private-state/run-files/run-1",
    }
    values.update(updates)
    return SlurmSubmitSpec(**values)  # type: ignore[arg-type]


def _job(
    job_id: str = "12345",
    submission_marker: str = _MARKER,
    submitted_at: str | None = _SUBMITTED_AT,
) -> SlurmJobRef:
    return SlurmJobRef(
        job_id=job_id,
        submission_marker=submission_marker,
        submitted_at=submitted_at,
    )


def _held(
    job_id: str = "12345",
    submission_marker: str = _MARKER,
    submitted_at: str | None = _SUBMITTED_AT,
    state: str = "PENDING",
    reason: str = "JobHeldUser",
) -> SlurmHeldJob:
    return SlurmHeldJob(
        job=_job(job_id, submission_marker, submitted_at),
        state=state,
        reason=reason,
    )


def _mapped(observation: SlurmObservation) -> SlurmMappedState:
    result = map_slurm_observation(observation)
    assert isinstance(result, SlurmMappedState)
    assert result.code
    return result


def _present(observation: SlurmObservation | None) -> SlurmObservation:
    assert observation is not None
    return observation


def _squeue_row(
    state: str,
    *,
    job_id: str = "12345",
    submitted_at: str = _SUBMITTED_AT,
    submission_marker: str = _MARKER,
) -> bytes:
    return f"{job_id}|{submitted_at}|{submission_marker}|{state}\n".encode()


def _sacct_row(
    state: str,
    exit_code: str = "0:0",
    *,
    job_id: str = "12345",
    submitted_at: str = _SUBMITTED_AT,
    submission_marker: str = _MARKER,
) -> bytes:
    return f"{job_id}|{submitted_at}|{submission_marker}|{state}|{exit_code}\n".encode()


def _squeue_hold_row(
    state: str = "PENDING",
    reason: str = "JobHeldUser",
    *,
    job_id: str = "12345",
    submitted_at: str = _SUBMITTED_AT,
    submission_marker: str = _MARKER,
) -> bytes:
    return f"{job_id}|{submitted_at}|{submission_marker}|{state}|{reason}\n".encode()


def test_scheduler_policy_is_strict_bounded_and_deterministic() -> None:
    first = _policy()
    second = SlurmSchedulerPolicy.from_mapping(dict(reversed(_policy_mapping().items())))

    assert first == second
    assert first.partition == "compute"
    assert first.account == "bioinfo"
    assert first.qos == "normal"
    assert first.time_limit == "08:00:00"
    assert first.cpus_per_task == 8
    assert first.memory_mib == 16_384
    assert first.submit_timeout_seconds == 60
    assert first.status_poll_seconds == 30
    assert first.max_pending_seconds == 3600


def test_scheduler_policy_identity_is_canonical_and_resource_bound() -> None:
    first = _policy()
    reordered = SlurmSchedulerPolicy.from_mapping(dict(reversed(_policy_mapping().items())))
    changed = SlurmSchedulerPolicy.from_mapping({**_policy_mapping(), "memory_mib": 16_385})

    assert canonical_scheduler_policy_bytes(first) == canonical_scheduler_policy_bytes(reordered)
    assert scheduler_policy_hash(first) == scheduler_policy_hash(reordered)
    assert len(scheduler_policy_hash(first)) == 64
    assert scheduler_policy_hash(changed) != scheduler_policy_hash(first)


@pytest.mark.parametrize("field", sorted(_policy_mapping()))
def test_scheduler_policy_requires_every_exact_field(field: str) -> None:
    value = _policy_mapping()
    del value[field]

    with pytest.raises((TypeError, ValueError)):
        SlurmSchedulerPolicy.from_mapping(value)


@pytest.mark.parametrize(
    "extra",
    [
        {"extra_flags": ["--exclusive"]},
        {"flags": "--wrap=id"},
        {"command": "id"},
        {"environment": {"SBATCH_ACCOUNT": "other"}},
        {"cancel_command": "scancel"},
    ],
)
def test_scheduler_policy_rejects_every_unreviewed_field(extra: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        SlurmSchedulerPolicy.from_mapping({**_policy_mapping(), **extra})


@pytest.mark.parametrize("field", ["partition", "account", "qos"])
@pytest.mark.parametrize(
    "injection",
    [
        "",
        "-debug",
        "normal,evil",
        "normal=evil",
        "normal;id",
        "normal\n#SBATCH --wrap=id",
        "normal\x00evil",
        "$(id)",
        "`id`",
        "normal/path",
        "normal value",
        "normal\u2028value",
    ],
)
def test_scheduler_identifiers_reject_flag_and_script_injection(
    field: str,
    injection: str,
) -> None:
    value = _policy_mapping()
    value[field] = injection

    with pytest.raises((TypeError, ValueError)):
        SlurmSchedulerPolicy.from_mapping(value)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("time_limit", "8:00:00"),
        ("time_limit", "08:00"),
        ("time_limit", "08:60:00"),
        ("time_limit", "08:00:60"),
        ("time_limit", "08:00:00\n#SBATCH --wrap=id"),
        ("time_limit", 80000),
        ("cpus_per_task", True),
        ("cpus_per_task", 0),
        ("cpus_per_task", 1_025),
        ("memory_mib", False),
        ("memory_mib", 1_023),
        ("memory_mib", 16 * 1024 * 1024 + 1),
        ("submit_timeout_seconds", True),
        ("submit_timeout_seconds", 0),
        ("submit_timeout_seconds", 2**63),
        ("status_poll_seconds", False),
        ("status_poll_seconds", 0),
        ("status_poll_seconds", 2**63),
        ("max_pending_seconds", True),
        ("max_pending_seconds", 0),
        ("max_pending_seconds", 2**63),
    ],
)
def test_scheduler_policy_rejects_malformed_time_and_numeric_budgets(
    field: str,
    invalid: object,
) -> None:
    value = _policy_mapping()
    value[field] = invalid

    with pytest.raises((TypeError, ValueError)):
        SlurmSchedulerPolicy.from_mapping(value)


@pytest.mark.parametrize(
    ("field", "injection"),
    [
        ("submission_marker", ""),
        ("submission_marker", "a" * 63),
        ("submission_marker", "a" * 65),
        ("submission_marker", "A" * 64),
        ("submission_marker", "g" * 64),
        ("submission_marker", "a" * 63 + "\n"),
        ("submission_marker", "a" * 63 + ";"),
        ("submission_marker", "a" * 63 + "\x00"),
        ("working_directory", "relative/work"),
        ("working_directory", "/srv/work\x00--wrap=id"),
        ("working_directory", "/srv/../tmp/work"),
        ("log_directory", "relative/logs"),
        ("log_directory", "/srv/log-%j"),
        ("log_directory", "/srv/log\n#SBATCH --wrap=id"),
        ("log_directory", "/srv/log\x00evil"),
    ],
)
def test_submit_spec_rejects_job_and_path_injection(field: str, injection: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        _submit_spec(**{field: injection})


def test_submit_spec_accepts_only_one_exact_lowercase_sha256_marker() -> None:
    spec = _submit_spec()

    assert spec.submission_marker == _MARKER


def test_fixed_scheduler_argv_have_no_generic_command_surface() -> None:
    spec = _submit_spec()
    job = _job()

    sbatch = build_sbatch_argv("/opt/slurm/bin/sbatch", spec)
    assert sbatch == (
        "/opt/slurm/bin/sbatch",
        "--parsable",
        "--hold",
        "--export=NIL",
        "--no-requeue",
        "--nodes=1",
        "--ntasks=1",
        "--cpus-per-task=8",
        "--mem=16384M",
        "--partition=compute",
        "--account=bioinfo",
        "--qos=normal",
        "--time=08:00:00",
        f"--job-name={_MARKER}",
        "--chdir=/srv/biopipe/work/run-1",
        "--output=/srv/biopipe/private-state/run-files/run-1/slurm-%j.stdout.log",
        "--error=/srv/biopipe/private-state/run-files/run-1/slurm-%j.stderr.log",
    )
    assert not any(argument.endswith((".sh", ".bash")) for argument in sbatch)

    squeue = build_squeue_argv("/opt/slurm/bin/squeue", job)
    assert squeue == (
        "/opt/slurm/bin/squeue",
        "--local",
        "--noheader",
        "--jobs=12345",
        "--states=all",
        "--format=%i|%V|%j|%T",
    )

    sacct = build_sacct_argv("/opt/slurm/bin/sacct", job)
    assert sacct == (
        "/opt/slurm/bin/sacct",
        "--local",
        "--noheader",
        "--parsable2",
        "--allocations",
        "--duplicates",
        "--jobs=12345",
        "--format=JobIDRaw,Submit,JobName%64,State%64,ExitCode",
    )

    hold_query = build_squeue_hold_argv("/opt/slurm/bin/squeue", job)
    assert hold_query == (
        "/opt/slurm/bin/squeue",
        "--local",
        "--noheader",
        "--jobs=12345",
        "--states=PENDING",
        "--format=%i|%V|%j|%T|%r",
    )

    held = parse_squeue_hold_output(_squeue_hold_row(), job)
    assert held is not None
    release = build_scontrol_release_argv("/opt/slurm/bin/scontrol", held)
    assert release == ("/opt/slurm/bin/scontrol", "release", "12345")

    discovery = build_squeue_discovery_argv("/opt/slurm/bin/squeue", _MARKER)
    assert discovery == (
        "/opt/slurm/bin/squeue",
        "--local",
        "--noheader",
        "--me",
        f"--name={_MARKER}",
        "--format=%i|%V|%j|%T",
    )

    flattened = "\n".join((*sbatch, *squeue, *sacct, *hold_query, *release, *discovery))
    assert "--wrap" not in flattened
    assert "scancel" not in flattened
    assert "bash" not in flattened
    assert "sh -c" not in flattened
    assert "--export=NONE" not in flattened


@pytest.mark.parametrize(
    ("builder", "binary"),
    [
        ("sbatch", "sbatch"),
        ("sbatch", "/opt/slurm/bin/not-sbatch"),
        ("sbatch", "/opt/slurm/unsafe:bin/sbatch"),
        ("squeue", "squeue"),
        ("squeue", "/opt/slurm/bin/not-squeue"),
        ("hold", "squeue"),
        ("hold", "/opt/slurm/bin/not-squeue"),
        ("hold", "/opt/slurm/unsafe:bin/squeue"),
        ("discovery", "squeue"),
        ("discovery", "/opt/slurm/bin/not-squeue"),
        ("sacct", "sacct"),
        ("sacct", "/opt/slurm/bin/not-sacct"),
        ("release", "scontrol"),
        ("release", "/opt/slurm/bin/not-scontrol"),
        ("release", "/opt/slurm/unsafe:bin/scontrol"),
    ],
)
def test_argv_builders_require_one_reviewed_absolute_binary(builder: str, binary: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        if builder == "sbatch":
            build_sbatch_argv(binary, _submit_spec())
        elif builder == "squeue":
            build_squeue_argv(binary, _job())
        elif builder == "hold":
            build_squeue_hold_argv(binary, _job())
        elif builder == "discovery":
            build_squeue_discovery_argv(binary, _MARKER)
        elif builder == "release":
            build_scontrol_release_argv(binary, _held())
        else:
            build_sacct_argv(binary, _job())


@pytest.mark.parametrize(
    "job_id",
    [
        "",
        "0",
        "00",
        "01",
        "-1",
        "+1",
        "12345_7",
        "12345.batch",
        "12345+1",
        "12345,54321",
        "12345 --flags=evil",
        "4294967296",
    ],
)
def test_scontrol_release_rejects_noncanonical_or_composite_job_ids(job_id: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        build_scontrol_release_argv("/opt/slurm/bin/scontrol", _held(job_id=job_id))


def test_scontrol_release_has_no_flags_or_generic_command_surface() -> None:
    held = _held(submitted_at=_SUBMITTED_AT)

    assert build_scontrol_release_argv("/opt/slurm/bin/scontrol", held) == (
        "/opt/slurm/bin/scontrol",
        "release",
        "12345",
    )
    with pytest.raises(TypeError):
        build_scontrol_release_argv(  # type: ignore[call-arg]
            "/opt/slurm/bin/scontrol",
            held,
            "--all",
        )
    with pytest.raises((TypeError, ValueError)):
        build_scontrol_release_argv(
            "/opt/slurm/bin/scontrol",
            "12345",  # type: ignore[arg-type]
        )


def test_scontrol_release_rejects_job_without_scheduler_submit_time_binding() -> None:
    provisional = _job(submitted_at=None)

    with pytest.raises(SlurmContractError, match="bind the scheduler submit time"):
        SlurmHeldJob(job=provisional, state="PENDING", reason="JobHeldUser")
    with pytest.raises(SlurmContractError, match="validated user-held job evidence"):
        build_scontrol_release_argv(  # type: ignore[arg-type]
            "/opt/slurm/bin/scontrol",
            provisional,
        )


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("RUNNING", "JobHeldUser"),
        ("PENDING", "JobHeldAdmin"),
        ("PENDING", "Dependency"),
        ("PENDING", "None"),
        ("PENDING", "JobHeldUser+"),
    ],
)
def test_held_job_type_requires_exact_pending_user_hold(state: str, reason: str) -> None:
    with pytest.raises(SlurmContractError):
        _held(state=state, reason=reason)


@pytest.mark.parametrize(
    "marker",
    ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "\n"],
)
def test_discovery_builder_rejects_noncanonical_markers(marker: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        build_squeue_discovery_argv("/opt/slurm/bin/squeue", marker)


def test_scheduler_environment_is_built_from_an_empty_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poisoned = {
        "SBATCH_ACCOUNT": "attacker",
        "SBATCH_WRAP": "id",
        "SLURM_CONF": "/tmp/attacker.conf",
        "SLURM_SPANK_PYTHONPATH": "/tmp/attacker",
        "SQUEUE_FORMAT": "%all",
        "SACCT_FORMAT": "all",
        "LD_PRELOAD": "/tmp/attacker.so",
        "PYTHONPATH": "/tmp/attacker",
        "BASH_ENV": "/tmp/attacker.sh",
        "HTTP_PROXY": "http://attacker.invalid",
        "AWS_SECRET_ACCESS_KEY": "secret",
    }
    for key, value in poisoned.items():
        monkeypatch.setenv(key, value)

    environment = build_scheduler_environment("/srv/biopipe/private-state/slurm-home")

    assert dict(environment) == {
        "HOME": "/srv/biopipe/private-state/slurm-home",
        "LANG": "C",
        "LC_ALL": "C",
    }
    assert not set(poisoned) & environment.keys()
    assert not any(key.startswith(("SBATCH_", "SLURM_")) for key in environment)
    with pytest.raises(TypeError):
        environment["HOME"] = "/tmp/attacker"  # type: ignore[index]


@pytest.mark.parametrize(
    "private_home",
    ["", "relative/home", "/srv/../tmp/home", "/srv/home\x00evil", "/srv/home\nBASH_ENV=x"],
)
def test_scheduler_environment_rejects_unsafe_private_home(private_home: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        build_scheduler_environment(private_home)


@pytest.mark.parametrize(
    "job_id",
    ["", "0", "00", "01", "-1", "+1", "1.0", "1_2", "1+2", "1.batch", " 1", "1 "],
)
def test_job_reference_rejects_noncanonical_or_structured_job_ids(job_id: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        _job(job_id)


@pytest.mark.parametrize(
    "marker",
    ["", "0" * 64, "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "\n"],
)
def test_job_reference_rejects_noncanonical_or_placeholder_markers(marker: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        _job(submission_marker=marker)


@pytest.mark.parametrize(
    "submitted_at",
    [
        "",
        "2026-07-19",
        "2026-07-19 12:34:56",
        "2026-07-19T12:34:56Z",
        "2026-07-19T12:34:56+00:00",
        "2026-07-19T12:34:56.000000",
        "2026-13-19T12:34:56",
        "2026-02-30T12:34:56",
        "2025-02-29T12:34:56",
        "2026-07-19t12:34:56",
        "2026-07-19T12:34:56\n",
        "2026-07-19T12:34:56\x00",
    ],
)
def test_job_reference_rejects_noncanonical_or_impossible_submit_times(
    submitted_at: str,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        _job(submitted_at=submitted_at)


def test_job_reference_has_no_cluster_or_federation_surface() -> None:
    with pytest.raises(TypeError):
        SlurmJobRef(  # type: ignore[call-arg]
            job_id="12345",
            submission_marker=_MARKER,
            cluster="alpha-1",
        )


def test_sbatch_parser_accepts_only_one_exact_job_reference() -> None:
    assert parse_sbatch_parsable_output(b"12345\n", _MARKER) == _job(submitted_at=None)

    with pytest.raises((TypeError, ValueError)):
        parse_sbatch_parsable_output(b"12345;alpha-1\n", _MARKER)


@pytest.mark.parametrize(
    "output",
    [
        b"",
        b"\n",
        b"0\n",
        b"01\n",
        b"12345 extra\n",
        b"12345\nwarning\n",
        b"12345_7\n",
        b"12345+1\n",
        b"12345.batch\n",
        b"12345;alpha;extra\n",
        b"1" * 129 + b"\n",
        b"12345\x00\n",
        b"\xff\n",
    ],
)
def test_sbatch_parser_rejects_ambiguous_or_injected_output(output: bytes) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_sbatch_parsable_output(output, _MARKER)


@pytest.mark.parametrize(
    "marker",
    ["", "0" * 64, "a" * 63, "a" * 65, "A" * 64, "g" * 64],
)
def test_sbatch_parser_rejects_invalid_marker_binding(marker: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_sbatch_parsable_output(b"12345\n", marker)


def test_squeue_parser_accepts_one_exact_allocation_row() -> None:
    provisional = _job(submitted_at=None)
    observation = _present(parse_squeue_output(_squeue_row("RUNNING"), provisional))

    assert observation.source == "squeue"
    assert observation.job == _job()
    assert observation.state == "RUNNING"
    assert observation.exit_code is None
    assert observation.cancelled_by_uid is None


def test_squeue_parser_distinguishes_no_row_from_malformed_output() -> None:
    assert parse_squeue_output(b"", _job()) is None


@pytest.mark.parametrize(
    "output",
    [
        _squeue_row("RUNNING", job_id="54321"),
        _squeue_row("RUNNING", job_id="12345.batch"),
        _squeue_row("RUNNING", job_id="12345_7"),
        _squeue_row("RUNNING", job_id="12345+1"),
        _squeue_row("RUNNING", submission_marker=_OTHER_MARKER),
        _squeue_row("RUNNING", submitted_at="2026-07-19T12:34:57"),
        _squeue_row("RUNNING", submitted_at="Unknown"),
        _squeue_row("CANCELLED by 1000"),
        _squeue_row("OUT_OF_MEM+"),
        _squeue_row("running"),
        _squeue_row("RUNNING").rstrip(b"\n") + b"|extra\n",
        _squeue_row("RUNNING") + _squeue_row("RUNNING"),
        _squeue_row("RUNNING").replace(b"RUNNING", b"RUNNING\x00"),
        b"\xff\n",
    ],
)
def test_squeue_parser_rejects_identity_mismatch_truncation_and_ambiguity(
    output: bytes,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_squeue_output(output, _job())


def test_squeue_hold_parser_proves_one_exact_user_held_job() -> None:
    provisional = _job(submitted_at=None)

    assert parse_squeue_hold_output(_squeue_hold_row(), provisional) == _held()


def test_squeue_hold_parser_empty_window_does_not_prove_a_hold() -> None:
    assert parse_squeue_hold_output(b"", _job()) is None


def test_squeue_hold_parser_accepts_scheduler_field_padding() -> None:
    row = (
        b"12345|" + _SUBMITTED_AT.encode() + b"|" + _MARKER.encode() + b"| PENDING | JobHeldUser \n"
    )

    assert parse_squeue_hold_output(row, _job()) == _held()


@pytest.mark.parametrize(
    "output",
    [
        _squeue_hold_row(job_id="54321"),
        _squeue_hold_row(job_id="12345.batch"),
        _squeue_hold_row(job_id="12345_7"),
        _squeue_hold_row(job_id="12345+1"),
        _squeue_hold_row(submission_marker=_OTHER_MARKER),
        _squeue_hold_row(submitted_at="2026-07-19T12:34:57"),
        _squeue_hold_row(submitted_at="Unknown"),
        _squeue_hold_row(state="RUNNING"),
        _squeue_hold_row(state="CONFIGURING"),
        _squeue_hold_row(reason="JobHeldAdmin"),
        _squeue_hold_row(reason="Dependency"),
        _squeue_hold_row(reason="None"),
        _squeue_hold_row(reason="JobHeldUser+"),
        _squeue_hold_row(reason="jobhelduser"),
        _squeue_hold_row().rstrip(b"\n") + b"|extra\n",
        _squeue_hold_row() + _squeue_hold_row(job_id="54321"),
        _squeue_hold_row().replace(b"JobHeldUser", b"JobHeldUser\x00"),
        b"\xff\n",
    ],
)
def test_squeue_hold_parser_rejects_mismatch_non_user_hold_and_ambiguity(
    output: bytes,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_squeue_hold_output(output, _job())


def test_squeue_hold_parser_rejects_unvalidated_expected_job() -> None:
    with pytest.raises(SlurmContractError, match="validated SlurmJobRef"):
        parse_squeue_hold_output(  # type: ignore[arg-type]
            _squeue_hold_row(),
            "12345",
        )


def test_sacct_parser_accepts_only_one_allocation_row() -> None:
    provisional = _job(submitted_at=None)
    observation = _present(parse_sacct_output(_sacct_row("COMPLETED"), provisional))

    assert observation.source == "sacct"
    assert observation.job == _job()
    assert observation.state == "COMPLETED"
    assert observation.exit_code == (0, 0)
    assert observation.cancelled_by_uid is None


def test_sacct_parser_accepts_fixed_width_state_padding() -> None:
    padded_state = b"COMPLETED".rjust(64, b" ")
    row = (
        b"12345|"
        + _SUBMITTED_AT.encode()
        + b"|"
        + _MARKER.encode()
        + b"|"
        + padded_state
        + b"|0:0\n"
    )

    observation = _present(parse_sacct_output(row, _job()))
    assert observation.state == "COMPLETED"
    assert observation.exit_code == (0, 0)


@pytest.mark.parametrize("uid", [0, 123, 4_294_967_295])
def test_sacct_parser_normalizes_exact_cancelled_by_uid_suffix(uid: int) -> None:
    observation = _present(parse_sacct_output(_sacct_row(f"CANCELLED by {uid}", "0:15"), _job()))

    assert observation.state == "CANCELLED"
    assert observation.cancelled_by_uid == uid
    assert observation.exit_code == (0, 15)


def test_sacct_parser_distinguishes_no_row_from_malformed_output() -> None:
    assert parse_sacct_output(b"", _job()) is None


@pytest.mark.parametrize(
    "output",
    [
        _sacct_row("COMPLETED", job_id="54321"),
        _sacct_row("COMPLETED", job_id="12345.batch"),
        _sacct_row("COMPLETED", job_id="12345.extern"),
        _sacct_row("COMPLETED", job_id="12345_7"),
        _sacct_row("COMPLETED", job_id="12345+1"),
        _sacct_row("COMPLETED", submission_marker=_OTHER_MARKER),
        _sacct_row("COMPLETED", submitted_at="2026-07-19T12:34:57"),
        _sacct_row("COMPLETED", submitted_at="Unknown"),
        _sacct_row("CANCELLED by 01", "0:15"),
        _sacct_row("CANCELLED by 4294967296", "0:15"),
        _sacct_row("CANCELLED  by 123", "0:15"),
        _sacct_row("CANCELLED by -1", "0:15"),
        _sacct_row("CANCELLED+", "0:15"),
        _sacct_row("CANCELLED by 123+", "0:15"),
        _sacct_row("OUT_OF_MEM+", "1:0"),
        _sacct_row("COMPLETED", "00:0"),
        _sacct_row("COMPLETED", "0:00"),
        _sacct_row("COMPLETED", "-1:0"),
        _sacct_row("COMPLETED", "256:0"),
        _sacct_row("COMPLETED", "0:256"),
        _sacct_row("COMPLETED", "0"),
        _sacct_row("COMPLETED").rstrip(b"\n") + b"|extra\n",
        _sacct_row("COMPLETED") + _sacct_row("COMPLETED"),
        _sacct_row("COMPLETED").replace(b"0:0", b"0:0\x00"),
        b"\xff\n",
    ],
)
def test_sacct_parser_rejects_identity_mismatch_truncation_and_bad_exit_codes(
    output: bytes,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_sacct_output(output, _job())


def test_squeue_discovery_resolves_one_exact_marker_bound_job() -> None:
    observation = _present(parse_squeue_discovery_output(_squeue_row("PENDING"), _MARKER))

    assert observation == SlurmObservation(
        source="squeue",
        job=_job(),
        state="PENDING",
    )


def test_squeue_discovery_empty_window_remains_unknown() -> None:
    assert parse_squeue_discovery_output(b"", _MARKER) is None


@pytest.mark.parametrize(
    "output",
    [
        _squeue_row("PENDING", submission_marker=_OTHER_MARKER),
        _squeue_row("PENDING", job_id="12345.batch"),
        _squeue_row("PENDING", submitted_at="Unknown"),
        _squeue_row("CANCELLED by 1000"),
        _squeue_row("OUT_OF_MEM+"),
        _squeue_row("PENDING") + _squeue_row("PENDING", job_id="54321"),
    ],
)
def test_squeue_discovery_rejects_mismatch_truncation_and_multiple_matches(
    output: bytes,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_squeue_discovery_output(output, _MARKER)


@pytest.mark.parametrize(
    "marker",
    ["", "0" * 64, "a" * 63, "a" * 65, "A" * 64, "g" * 64],
)
def test_squeue_discovery_parser_rejects_invalid_expected_marker(marker: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_squeue_discovery_output(_squeue_row("PENDING"), marker)


@pytest.mark.parametrize(
    "state",
    ["PENDING", "CONFIGURING", "EXPEDITING", "POWER_UP_NODE", "RESV_DEL_HOLD"],
)
def test_every_reviewed_queue_state_maps_to_queued(state: str) -> None:
    observation = _present(parse_squeue_output(_squeue_row(state), _job()))
    assert _mapped(observation) == SlurmMappedState(
        state="queued",
        code=f"SLURM_{state}",
    )


@pytest.mark.parametrize(
    "state",
    [
        "RUNNING",
        "SUSPENDED",
        "COMPLETING",
        "SIGNALING",
        "STAGE_OUT",
        "STOPPED",
        "RESIZING",
        "UPDATE_DB",
    ],
)
def test_every_reviewed_execution_state_maps_to_active(state: str) -> None:
    observation = _present(parse_squeue_output(_squeue_row(state), _job()))
    assert _mapped(observation) == SlurmMappedState(
        state="active",
        code=f"SLURM_{state}",
    )


@pytest.mark.parametrize(
    "state",
    ["REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SPECIAL_EXIT"],
)
def test_every_restart_or_requeue_state_requires_reconciliation(state: str) -> None:
    observation = _present(parse_squeue_output(_squeue_row(state), _job()))

    assert _mapped(observation) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_RESTART_REQUIRES_RECONCILIATION",
    )


def test_only_sacct_completed_zero_exit_confirms_success() -> None:
    completed = _present(parse_sacct_output(_sacct_row("COMPLETED"), _job()))
    nonzero = _present(parse_sacct_output(_sacct_row("COMPLETED", "1:0"), _job()))
    signalled = _present(parse_sacct_output(_sacct_row("COMPLETED", "0:9"), _job()))
    squeue_only = _present(parse_squeue_output(_squeue_row("COMPLETED"), _job()))

    assert _mapped(completed) == SlurmMappedState(
        state="succeeded",
        code="SLURM_COMPLETED",
    )
    assert _mapped(nonzero) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_SUCCESS_EXIT_CONFLICT",
    )
    assert _mapped(signalled) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_SUCCESS_EXIT_CONFLICT",
    )
    assert _mapped(squeue_only) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_TERMINAL_REQUIRES_SACCT",
    )


@pytest.mark.parametrize(
    "state",
    [
        "BOOT_FAIL",
        "CANCELLED",
        "DEADLINE",
        "FAILED",
        "NODE_FAIL",
        "OUT_OF_MEMORY",
        "PREEMPTED",
        "TIMEOUT",
        "LAUNCH_FAILED",
        "RECONFIG_FAIL",
        "REVOKED",
    ],
)
def test_every_sacct_terminal_failure_state_maps_to_failed(state: str) -> None:
    observation = _present(parse_sacct_output(_sacct_row(state, "1:0"), _job()))
    assert _mapped(observation) == SlurmMappedState(
        state="failed",
        code=f"SLURM_{state}",
    )


@pytest.mark.parametrize(
    "state",
    [
        "COMPLETED",
        "BOOT_FAIL",
        "CANCELLED",
        "DEADLINE",
        "FAILED",
        "NODE_FAIL",
        "OUT_OF_MEMORY",
        "PREEMPTED",
        "TIMEOUT",
        "LAUNCH_FAILED",
        "RECONFIG_FAIL",
        "REVOKED",
    ],
)
def test_every_squeue_terminal_state_requires_sacct_evidence(state: str) -> None:
    observation = _present(parse_squeue_output(_squeue_row(state), _job()))

    assert _mapped(observation) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_TERMINAL_REQUIRES_SACCT",
    )


def test_terminal_state_exit_code_conflicts_and_missing_evidence_are_indeterminate() -> None:
    job = _job()
    failed_zero = _present(parse_sacct_output(_sacct_row("FAILED"), job))
    completed_without_exit = SlurmObservation(
        source="sacct",
        job=job,
        state="COMPLETED",
        exit_code=None,
    )

    assert _mapped(failed_zero) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_FAILURE_EXIT_CONFLICT",
    )
    assert _mapped(completed_without_exit) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_EXIT_CODE_UNAVAILABLE",
    )


@pytest.mark.parametrize("source", ["squeue", "sacct"])
@pytest.mark.parametrize("state", ["UNKNOWN", "FUTURE_STATE"])
def test_unknown_canonical_states_fail_closed(source: str, state: str) -> None:
    if source == "squeue":
        observation = _present(parse_squeue_output(_squeue_row(state), _job()))
    else:
        observation = _present(parse_sacct_output(_sacct_row(state), _job()))
    assert _mapped(observation) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_STATE_UNKNOWN",
    )


@pytest.mark.parametrize("source", ["squeue", "sacct"])
@pytest.mark.parametrize("state", ["COMPLETED+", "running"])
def test_noncanonical_states_are_rejected(source: str, state: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        if source == "squeue":
            parse_squeue_output(_squeue_row(state), _job())
        else:
            parse_sacct_output(_sacct_row(state), _job())


@pytest.mark.parametrize(
    ("source", "state", "uid"),
    [
        ("squeue", "CANCELLED", 123),
        ("sacct", "FAILED", 123),
        ("sacct", "CANCELLED", -1),
        ("sacct", "CANCELLED", 4_294_967_296),
        ("sacct", "CANCELLED", True),
    ],
)
def test_observation_model_rejects_uid_outside_exact_sacct_cancelled_suffix(
    source: str,
    state: str,
    uid: int,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        SlurmObservation(  # type: ignore[arg-type]
            source=source,
            job=_job(),
            state=state,
            exit_code=None,
            cancelled_by_uid=uid,
        )


def test_reconcile_empty_observation_window_remains_indeterminate() -> None:
    assert reconcile_slurm_observations(None, None) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_OBSERVATION_MISSING",
    )


@pytest.mark.parametrize(
    ("queue_state", "accounting_state", "expected"),
    [
        ("PENDING", None, SlurmMappedState("queued", "SLURM_PENDING")),
        ("RUNNING", None, SlurmMappedState("active", "SLURM_RUNNING")),
        (None, "RUNNING", SlurmMappedState("active", "SLURM_RUNNING")),
        (None, "COMPLETED", SlurmMappedState("succeeded", "SLURM_COMPLETED")),
        (None, "FAILED", SlurmMappedState("failed", "SLURM_FAILED")),
        ("RUNNING", "RUNNING", SlurmMappedState("active", "SLURM_RUNNING")),
    ],
)
def test_reconcile_accepts_one_source_or_matching_sources(
    queue_state: str | None,
    accounting_state: str | None,
    expected: SlurmMappedState,
) -> None:
    queue = (
        None
        if queue_state is None
        else _present(parse_squeue_output(_squeue_row(queue_state), _job()))
    )
    accounting = (
        None
        if accounting_state is None
        else _present(
            parse_sacct_output(
                _sacct_row(
                    accounting_state,
                    "0:0" if accounting_state == "COMPLETED" else "1:0",
                ),
                _job(),
            )
        )
    )

    assert reconcile_slurm_observations(queue, accounting) == expected


def test_reconcile_conflicting_sources_and_attempt_identities_fail_closed() -> None:
    queue = _present(parse_squeue_output(_squeue_row("RUNNING"), _job()))
    contradictory = _present(parse_sacct_output(_sacct_row("COMPLETED"), _job()))
    other_attempt = SlurmObservation(
        source="sacct",
        job=_job(submitted_at="2026-07-19T12:34:57"),
        state="RUNNING",
        exit_code=(1, 0),
    )

    expected = SlurmMappedState(
        state="indeterminate",
        code="SLURM_OBSERVATION_CONFLICT",
    )
    assert reconcile_slurm_observations(queue, contradictory) == expected
    assert reconcile_slurm_observations(queue, other_attempt) == expected


@pytest.mark.parametrize(
    "previous",
    [
        SlurmMappedState("succeeded", "SLURM_COMPLETED"),
        SlurmMappedState("failed", "SLURM_FAILED"),
    ],
)
def test_reconcile_terminal_state_survives_empty_or_matching_later_windows(
    previous: SlurmMappedState,
) -> None:
    assert reconcile_slurm_observations(None, None, previous) == previous

    state = "COMPLETED" if previous.state == "succeeded" else "FAILED"
    accounting = _present(
        parse_sacct_output(
            _sacct_row(state, "0:0" if state == "COMPLETED" else "1:0"),
            _job(),
        )
    )
    assert reconcile_slurm_observations(None, accounting, previous) == previous


@pytest.mark.parametrize(
    ("previous", "queue", "accounting"),
    [
        (SlurmMappedState("succeeded", "SLURM_COMPLETED"), "RUNNING", None),
        (SlurmMappedState("succeeded", "SLURM_COMPLETED"), None, "FAILED"),
        (SlurmMappedState("failed", "SLURM_FAILED"), None, "COMPLETED"),
    ],
)
def test_reconcile_never_regresses_or_flips_a_terminal_state(
    previous: SlurmMappedState,
    queue: str | None,
    accounting: str | None,
) -> None:
    queue_observation = (
        None if queue is None else _present(parse_squeue_output(_squeue_row(queue), _job()))
    )
    accounting_observation = (
        None
        if accounting is None
        else _present(
            parse_sacct_output(
                _sacct_row(accounting, "0:0" if accounting == "COMPLETED" else "1:0"),
                _job(),
            )
        )
    )

    assert reconcile_slurm_observations(
        queue_observation,
        accounting_observation,
        previous,
    ) == SlurmMappedState(
        state="indeterminate",
        code="SLURM_TERMINAL_STATE_REGRESSION",
    )


def test_reconcile_rejects_wrong_sources_and_unvalidated_values() -> None:
    queue = _present(parse_squeue_output(_squeue_row("RUNNING"), _job()))
    accounting = _present(parse_sacct_output(_sacct_row("RUNNING", "1:0"), _job()))

    with pytest.raises((TypeError, ValueError)):
        reconcile_slurm_observations(accounting, None)
    with pytest.raises((TypeError, ValueError)):
        reconcile_slurm_observations(None, queue)
    with pytest.raises((TypeError, ValueError)):
        reconcile_slurm_observations("RUNNING", None)  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        reconcile_slurm_observations(None, None, "succeeded")  # type: ignore[arg-type]


@pytest.mark.parametrize("operation", ["slurm", "cancel"])
def test_dormant_scheduler_and_cancel_operations_remain_unsupported(
    operation: str,
) -> None:
    with pytest.raises(AgentFailure) as raised:
        parse_request(
            {
                "protocol_version": "1.0",
                "request_id": "request-1",
                "operation": operation,
                "payload": {},
            }
        )

    assert raised.value.return_code == ReturnCode.UNSUPPORTED_OPERATION
    assert raised.value.code == "UNSUPPORTED_OPERATION"


@pytest.mark.parametrize("module_name", ["main.py", "config.py", "runner.py", "protocol.py"])
def test_production_entry_points_do_not_import_dormant_slurm_contract(
    module_name: str,
) -> None:
    source_path = Path(__file__).parents[1] / "src" / "bioexec" / module_name
    syntax = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))

    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all(alias.name != "bioexec.slurm" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (
                (node.level == 1 and node.module == "slurm")
                or node.module == "bioexec.slurm"
                or (
                    node.level == 1
                    and node.module is None
                    and any(alias.name == "slurm" for alias in node.names)
                )
            )


def test_contract_api_is_pure_and_never_invokes_host_or_network_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    spec = _submit_spec(policy=policy)
    job = _job()
    held = _held()

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the dormant Slurm contract performed an external operation")

    patches: tuple[tuple[object, str], ...] = (
        (subprocess, "run"),
        (subprocess, "Popen"),
        (os, "system"),
        (os, "getenv"),
        (socket, "socket"),
    )
    for owner, name in patches:
        monkeypatch.setattr(owner, name, forbidden)

    calls: tuple[Callable[[], object], ...] = (
        lambda: build_sbatch_argv("/opt/slurm/bin/sbatch", spec),
        lambda: build_squeue_argv("/opt/slurm/bin/squeue", job),
        lambda: build_sacct_argv("/opt/slurm/bin/sacct", job),
        lambda: build_squeue_hold_argv("/opt/slurm/bin/squeue", job),
        lambda: build_scontrol_release_argv("/opt/slurm/bin/scontrol", held),
        lambda: build_squeue_discovery_argv("/opt/slurm/bin/squeue", _MARKER),
        lambda: build_scheduler_environment("/srv/biopipe/private-state/slurm-home"),
        lambda: parse_sbatch_parsable_output(b"12345\n", _MARKER),
        lambda: parse_squeue_output(_squeue_row("RUNNING"), job),
        lambda: parse_squeue_hold_output(_squeue_hold_row(), job),
        lambda: parse_sacct_output(_sacct_row("COMPLETED"), job),
        lambda: parse_squeue_discovery_output(_squeue_row("PENDING"), _MARKER),
    )
    for call in calls:
        call()

    queue = _present(parse_squeue_output(_squeue_row("RUNNING"), job))
    accounting = _present(parse_sacct_output(_sacct_row("COMPLETED"), job))
    assert _mapped(queue).state == "active"
    assert _mapped(accounting).state == "succeeded"
    assert reconcile_slurm_observations(None, accounting).state == "succeeded"
