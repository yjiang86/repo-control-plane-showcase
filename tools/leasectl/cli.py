from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from tools.leasectl.core import LockCoordinator, LockError


def _paths(args: argparse.Namespace) -> list[dict[str, str]] | None:
    rules = [
        *({"kind": "exact", "path": path} for path in args.path_exact),
        *({"kind": "prefix", "path": path} for path in args.path_prefix),
    ]
    return rules or None


def _coordinator(args: argparse.Namespace) -> LockCoordinator:
    return LockCoordinator(Path(args.repo_root), git_only=args.git_only)


def command_status(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            _coordinator(args).status(),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_acquire(args: argparse.Namespace) -> int:
    result = _coordinator(args).acquire(
        lock_kind=args.lock_kind,
        task=args.task,
        owner=args.owner,
        ttl_seconds=args.ttl_seconds,
        paths=_paths(args),
        nonce=args.nonce,
        lock_id=args.lock_id,
        base_head=args.base_head,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_renew(args: argparse.Namespace) -> int:
    result = _coordinator(args).renew(
        lock_id=args.lock_id,
        owner=args.owner,
        nonce=args.nonce,
        new_nonce=args.new_nonce,
        ttl_seconds=args.ttl_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_renew_active(args: argparse.Namespace) -> int:
    result = _coordinator(args).renew_active(
        lock_id=args.lock_id,
        owner=args.owner,
        nonce=args.nonce,
        new_nonce=args.new_nonce,
        ttl_seconds=args.ttl_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_release(args: argparse.Namespace) -> int:
    result = _coordinator(args).release(
        lock_id=args.lock_id,
        owner=args.owner,
        nonce=args.nonce,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leasectl",
        description=(
            "Single-host path and Git mutation locks for concurrency only. "
            "Locks do not grant task, scientific, or publication authority."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser(
        "status",
        help="read ephemeral lock state without creating or changing it",
    )
    status.add_argument("--repo-root", required=True)
    status.set_defaults(func=command_status)

    acquire = subparsers.add_parser("acquire", help="atomically acquire one lock")
    acquire.add_argument("--repo-root", required=True)
    acquire.add_argument(
        "--lock-kind",
        "--lease-class",
        dest="lock_kind",
        required=True,
        help=(
            "PATH_LOCK or GIT_MUTATION_LOCK; legacy PROJECT_PATH_LEASE and "
            "GIT_PUBLICATION_LEASE are accepted as naming aliases only"
        ),
    )
    acquire.add_argument("--task", "--task-package-id", dest="task", required=True)
    acquire.add_argument("--owner", required=True)
    acquire.add_argument("--base-head")
    acquire.add_argument(
        "--path-exact",
        "--write-exact",
        dest="path_exact",
        action="append",
        default=[],
    )
    acquire.add_argument(
        "--path-prefix",
        "--write-prefix",
        dest="path_prefix",
        action="append",
        default=[],
    )
    acquire.add_argument("--ttl-seconds", type=int, required=True)
    acquire.add_argument("--nonce")
    acquire.add_argument("--lock-id", "--lease-id", dest="lock_id")
    acquire.set_defaults(func=command_acquire)

    renew = subparsers.add_parser(
        "renew",
        help="renew or recover a stale lock using its owner and current nonce",
    )
    renew_active = subparsers.add_parser(
        "renew-active",
        help="strictly renew an active lock; expired locks are never recovered",
    )
    release = subparsers.add_parser(
        "release",
        help="release a lock; no publication outcome or authority receipt is created",
    )
    for command, callback in (
        (renew, command_renew),
        (renew_active, command_renew_active),
        (release, command_release),
    ):
        command.add_argument("--repo-root", required=True)
        command.add_argument("--lock-id", "--lease-id", dest="lock_id", required=True)
        command.add_argument("--owner", required=True)
        command.add_argument("--nonce", required=True)
        if command is not release:
            command.add_argument("--new-nonce")
            command.add_argument("--ttl-seconds", type=int, required=True)
        command.set_defaults(func=callback)
    for command in (status, acquire, renew, renew_active, release):
        command.add_argument(
            "--git-only", action="store_true",
            help="coordinate Git locks across linked worktrees; binds the acquiring root, rejects PATH_LOCK",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (LockError, OSError, ValueError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "error_code": "LOCK_COORDINATION_FAILED",
                    "error": str(error),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
