#!/usr/bin/env python3
"""Create or offline-verify a privacy-safe internal-pilot review draft."""

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
from biopipe.release_evidence.pilot import (  # noqa: E402
    SanitizedPilotRecord,
    create_pilot_evidence,
    verify_pilot_evidence,
)


class PrivacySafeArgumentParser(argparse.ArgumentParser):
    """Reject malformed invocations without echoing operator-supplied values."""

    def error(self, _message: str) -> Never:
        self.exit(2, "collect_internal_pilot_evidence.py: invalid arguments\n")


def build_parser() -> argparse.ArgumentParser:
    parser = PrivacySafeArgumentParser(
        prog="collect_internal_pilot_evidence.py",
        description=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser(
        "create",
        help="Create one blocked review-draft bundle from a strict sanitized record.",
    )
    create.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    create.add_argument("--candidate-evidence", type=Path, required=True)
    create.add_argument("--release-acceptance-evidence", type=Path, required=True)
    create.add_argument("--real-host-evidence", type=Path, required=True)
    create.add_argument("--sanitized-record", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--created-at", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="Verify structure, deterministic projection, and checksums fully offline.",
    )
    verify.add_argument("--directory", type=Path, required=True)

    subparsers.add_parser(
        "schema",
        help="Print the internal strict sanitized-record schema without reading private data.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            verification = create_pilot_evidence(
                repository=args.repository,
                candidate_evidence=args.candidate_evidence,
                release_acceptance_evidence=args.release_acceptance_evidence,
                real_host_evidence=args.real_host_evidence,
                sanitized_record=args.sanitized_record,
                output_directory=args.output,
                created_at=args.created_at,
            )
            result = verification.model_dump(mode="json")
            result["status"] = "pilot_summary_bundle_created_unreviewed"
        elif args.command == "verify":
            verification = verify_pilot_evidence(args.directory)
            result = verification.model_dump(mode="json")
            result["status"] = "pilot_summary_bundle_verified_offline"
        else:
            result = SanitizedPilotRecord.model_json_schema(mode="validation")
        print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
        return 0
    except BioPipeError as error:
        print(error.to_json(), file=sys.stderr)
        return 2
    except Exception:
        internal_error = BioPipeError(
            ErrorCode.INTERNAL_ERROR,
            "Internal pilot evidence failed without exposing private diagnostics.",
            remediation=["Review the strict sanitized inputs and retry with a new output."],
        )
        print(internal_error.to_json(), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
