from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .core import (
    CheckpointError,
    ExportRequest,
    FreezeRequest,
    export_checkpoint,
    freeze_checkpoint,
    inspect_checkpoint,
    observe_subject,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devcheckpointctl",
        description="Freeze exact-path development progress without changing the worktree, index, branch, or remote",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--repo-root", type=Path, required=True)
    freeze.add_argument("--activity", required=True)
    freeze.add_argument("--label", required=True)
    freeze.add_argument("--owner", required=True)
    freeze.add_argument("--task", required=True)
    freeze.add_argument("--path", action="append", default=[])
    freeze.add_argument("--expected-subject-sha256")

    subject = subparsers.add_parser("subject", help="Read base/path/content identity before releasing PATH")
    subject.add_argument("--repo-root", type=Path, required=True)
    subject.add_argument("--path", action="append", required=True)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--repo-root", type=Path, required=True)
    inspect.add_argument("--activity", required=True)

    export = subparsers.add_parser("export")
    export.add_argument("--repo-root", type=Path, required=True)
    export.add_argument("--activity", required=True)
    export.add_argument("--output", type=Path, required=True)

    list_command = subparsers.add_parser("list")
    list_command.add_argument("--repo-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "freeze":
            result = freeze_checkpoint(
                FreezeRequest(
                    repo_root=args.repo_root,
                    activity=args.activity,
                    label=args.label,
                    owner=args.owner,
                    task=args.task,
                    paths=tuple(args.path),
                    expected_subject_sha256=args.expected_subject_sha256,
                )
            )
        elif args.command == "subject":
            result = observe_subject(args.repo_root, tuple(args.path))
        elif args.command == "inspect":
            result = inspect_checkpoint(args.repo_root, args.activity)
        elif args.command == "export":
            result = export_checkpoint(
                ExportRequest(
                    repo_root=args.repo_root,
                    activity=args.activity,
                    output=args.output,
                )
            )
        else:
            from .core import list_checkpoints

            result = list_checkpoints(args.repo_root)
    except CheckpointError as error:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason_code": error.reason_code,
                    "detail": error.detail,
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
