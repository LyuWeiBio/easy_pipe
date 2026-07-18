#!/usr/bin/env python3
"""Create or offline-verify sanitized release-acceptance CI evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from biopipe.errors import BioPipeError, ErrorCode  # noqa: E402
from biopipe.release_evidence.acceptance import (  # noqa: E402
    AcceptanceArtifactPaths,
    create_release_acceptance_evidence,
    verify_native_environment_export,
    verify_release_acceptance_evidence,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create one sanitized Linux CI bundle.")
    create.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--release-id", required=True)
    create.add_argument("--created-at", required=True)
    create.add_argument("--ci-run-id", required=True)
    create.add_argument("--environment-export", type=Path, required=True)
    create.add_argument("--test-result", type=Path, required=True)
    create.add_argument("--wheel", type=Path, required=True)
    create.add_argument("--sdist", type=Path, required=True)
    create.add_argument("--bioprobe-first", type=Path, required=True)
    create.add_argument("--bioprobe-second", type=Path, required=True)
    create.add_argument("--bioexec-first", type=Path, required=True)
    create.add_argument("--bioexec-second", type=Path, required=True)

    verify_export = subparsers.add_parser(
        "verify-export", help="Bind a native export to one committed platform lock."
    )
    verify_export.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    verify_export.add_argument("--platform", choices=("linux-64", "osx-arm64"), required=True)
    verify_export.add_argument("--environment-export", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="Verify one bundle fully offline.")
    verify.add_argument("--directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            result = create_release_acceptance_evidence(
                repository=args.repository,
                output_directory=args.output,
                release_id=args.release_id,
                created_at=args.created_at,
                ci_run_id=args.ci_run_id,
                environment_export=args.environment_export,
                test_result=args.test_result,
                artifact_paths=AcceptanceArtifactPaths(
                    wheel=args.wheel,
                    sdist=args.sdist,
                    bioprobe_first=args.bioprobe_first,
                    bioprobe_second=args.bioprobe_second,
                    bioexec_first=args.bioexec_first,
                    bioexec_second=args.bioexec_second,
                ),
            )
        elif args.command == "verify-export":
            result = verify_native_environment_export(
                repository=args.repository,
                environment_export=args.environment_export,
                platform=args.platform,
            )
        else:
            result = verify_release_acceptance_evidence(args.directory)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except BioPipeError as error:
        print(error.to_json(), file=sys.stderr)
        return 2
    except Exception:
        internal_error = BioPipeError(
            ErrorCode.INTERNAL_ERROR,
            "Release acceptance evidence failed without exposing internal diagnostics.",
            remediation=["Review the fixed inputs and retry."],
        )
        print(internal_error.to_json(), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
