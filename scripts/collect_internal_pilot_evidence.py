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
from biopipe.release_evidence.pilot_record import (  # noqa: E402
    create_unexecuted_pilot_record,
    validate_sanitized_pilot_record,
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

    init_record = subparsers.add_parser(
        "init-record",
        help="Create one strict all-unexecuted record that remains blocked.",
    )
    init_record.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    init_record.add_argument("--output", type=Path, required=True)
    init_record.add_argument("--pilot-id", required=True)
    init_record.add_argument("--environment-id", required=True)
    init_record.add_argument("--recorded-at", required=True)
    init_record.add_argument("--release-id", required=True)
    init_record.add_argument("--source-git-commit", required=True)
    init_record.add_argument("--candidate-manifest-sha256", required=True)
    init_record.add_argument("--release-acceptance-manifest-sha256", required=True)
    init_record.add_argument("--real-host-manifest-sha256", required=True)

    validate_record = subparsers.add_parser(
        "validate-record",
        help="Validate one strict sanitized record offline without authenticating its facts.",
    )
    validate_record.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    validate_record.add_argument("--sanitized-record", type=Path, required=True)

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
            evidence_verification = create_pilot_evidence(
                repository=args.repository,
                candidate_evidence=args.candidate_evidence,
                release_acceptance_evidence=args.release_acceptance_evidence,
                real_host_evidence=args.real_host_evidence,
                sanitized_record=args.sanitized_record,
                output_directory=args.output,
                created_at=args.created_at,
            )
            result = evidence_verification.model_dump(mode="json")
            result["status"] = "pilot_summary_bundle_created_unreviewed"
        elif args.command == "init-record":
            record_validation = create_unexecuted_pilot_record(
                repository=args.repository,
                output_file=args.output,
                pilot_id=args.pilot_id,
                environment_id=args.environment_id,
                recorded_at=args.recorded_at,
                release_id=args.release_id,
                source_git_commit=args.source_git_commit,
                candidate_manifest_sha256=args.candidate_manifest_sha256,
                release_acceptance_manifest_sha256=(args.release_acceptance_manifest_sha256),
                real_host_manifest_sha256=args.real_host_manifest_sha256,
            )
            result = record_validation.model_dump(mode="json")
            result["status"] = "pilot_record_initialized_unexecuted_blocked"
        elif args.command == "validate-record":
            record_validation = validate_sanitized_pilot_record(
                repository=args.repository,
                record_file=args.sanitized_record,
            )
            result = record_validation.model_dump(mode="json")
            result["status"] = "pilot_record_strict_format_validated_only"
        elif args.command == "verify":
            evidence_verification = verify_pilot_evidence(args.directory)
            result = evidence_verification.model_dump(mode="json")
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
