"""Repository-local command-line interface for M6.1 evidence tooling."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.release_evidence.generator import (
    ReleaseArtifactPaths,
    create_release_evidence,
    instantiate_release_checklist_file,
    seal_release_evidence,
    verify_release_evidence,
)


def build_parser(*, default_repository: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and verify unsigned, create-only M6.1 release evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create one sealed unsigned bundle.")
    _identity_arguments(create, default_repository=default_repository)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--source-archive", type=Path, required=True)
    create.add_argument("--wheel", type=Path, required=True)
    create.add_argument("--sdist", type=Path, required=True)
    create.add_argument("--bioprobe", type=Path, required=True)
    create.add_argument("--bioexec", type=Path, required=True)

    checklist = subparsers.add_parser(
        "checklist", help="Instantiate one unsigned checklist create-only."
    )
    _identity_arguments(checklist, default_repository=default_repository)
    checklist.add_argument("--output", type=Path, required=True)

    checksums = subparsers.add_parser(
        "checksums", help="Seal one exact unsealed evidence directory create-only."
    )
    checksums.add_argument("--directory", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="Verify a sealed bundle fully offline.")
    verify.add_argument("--directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None, *, default_repository: Path | None = None) -> int:
    root = default_repository or Path.cwd()
    parser = build_parser(default_repository=root)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result: Any = create_release_evidence(
                repository=args.repository,
                output_directory=args.output,
                release_id=args.release_id,
                created_at=args.created_at,
                created_by=args.created_by,
                artifact_paths=ReleaseArtifactPaths(
                    source_archive=args.source_archive,
                    wheel=args.wheel,
                    sdist=args.sdist,
                    bioprobe=args.bioprobe,
                    bioexec=args.bioexec,
                ),
            ).model_dump(mode="json")
            result["status"] = "evidence_created_unreviewed"
        elif args.command == "checklist":
            result = instantiate_release_checklist_file(
                repository=args.repository,
                output_file=args.output,
                release_id=args.release_id,
                created_at=args.created_at,
                created_by=args.created_by,
            )
            result["status"] = "checklist_instantiated_unreviewed"
        elif args.command == "checksums":
            result = seal_release_evidence(args.directory).model_dump(mode="json")
            result["status"] = "evidence_integrity_sealed"
        else:
            result = verify_release_evidence(args.directory).model_dump(mode="json")
            result["status"] = "evidence_integrity_verified"
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except BioPipeError as error:
        print(error.to_json(), file=sys.stderr)
        return 2
    except Exception:
        internal_error = BioPipeError(
            ErrorCode.INTERNAL_ERROR,
            "Release evidence failed without exposing internal diagnostics.",
            remediation=["Review the fixed inputs and run the command again."],
        )
        print(internal_error.to_json(), file=sys.stderr)
        return 2


def _identity_arguments(parser: argparse.ArgumentParser, *, default_repository: Path) -> None:
    parser.add_argument("--repository", type=Path, default=default_repository)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--created-by", required=True)


__all__ = ["build_parser", "main"]
