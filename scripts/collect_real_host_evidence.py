#!/usr/bin/env python3
"""Create or offline-verify sanitized operator real-host evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Never

sys.dont_write_bytecode = True

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from biopipe.errors import BioPipeError, ErrorCode  # noqa: E402
from biopipe.release_evidence.real_host import (  # noqa: E402
    RealHostEvidenceInputs,
    create_real_host_acceptance_evidence,
    verify_real_host_acceptance_evidence,
)


class PrivacySafeArgumentParser(argparse.ArgumentParser):
    """Reject malformed invocations without echoing operator-supplied values."""

    def error(self, _message: str) -> Never:
        self.exit(2, "collect_real_host_evidence.py: invalid arguments\n")


def build_parser() -> argparse.ArgumentParser:
    parser = PrivacySafeArgumentParser(prog="collect_real_host_evidence.py", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create one blocked operator bundle.")
    create.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    create.add_argument("--candidate-evidence", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--created-at", required=True)
    for name in (
        "validation-report",
        "test-report",
        "preflight-report",
        "run-report",
        "status-report",
        "execution-profile",
        "approval-denial",
        "audit-before-denial",
        "audit-after-denial",
        "audit-final",
        "probe-health",
        "executor-health",
        "multiqc-report",
        "multiqc-data",
        "bioprobe",
        "bioexec",
    ):
        create.add_argument(f"--{name}", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="Verify one bundle fully offline.")
    verify.add_argument("--directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            result = create_real_host_acceptance_evidence(
                repository=args.repository,
                candidate_evidence=args.candidate_evidence,
                output_directory=args.output,
                created_at=args.created_at,
                inputs=RealHostEvidenceInputs(
                    validation_report=args.validation_report,
                    test_report=args.test_report,
                    preflight_report=args.preflight_report,
                    run_report=args.run_report,
                    status_report=args.status_report,
                    execution_profile=args.execution_profile,
                    approval_denial=args.approval_denial,
                    audit_before_denial=args.audit_before_denial,
                    audit_after_denial=args.audit_after_denial,
                    audit_final=args.audit_final,
                    probe_health=args.probe_health,
                    executor_health=args.executor_health,
                    multiqc_report=args.multiqc_report,
                    multiqc_data=args.multiqc_data,
                    bioprobe=args.bioprobe,
                    bioexec=args.bioexec,
                ),
            )
        else:
            result = verify_real_host_acceptance_evidence(args.directory)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except BioPipeError as error:
        print(error.to_json(), file=sys.stderr)
        return 2
    except Exception:
        internal_error = BioPipeError(
            ErrorCode.INTERNAL_ERROR,
            "Real-host evidence collection failed without exposing private diagnostics.",
            remediation=["Review the fixed private inputs and retry in a new output directory."],
        )
        print(internal_error.to_json(), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
