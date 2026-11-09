"""Canonical byte serialization for frozen Git patches."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import shutil


# These options are the frozen-patch wire format.  Keep them explicit so patch
# identity cannot depend on host abbreviation, diff, rename, prefix, color, or
# hunk-layout configuration.
CANONICAL_PATCH_DIFF_OPTIONS: tuple[str, ...] = (
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--no-color",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--diff-algorithm=myers",
    "--no-indent-heuristic",
    "--unified=3",
    "--inter-hunk-context=0",
)

CANONICAL_PATCH_GIT_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.attributesFile", os.devnull),
    ("core.quotePath", "true"),
    ("diff.orderFile", os.devnull),
)

CANONICAL_PATCH_ENVIRONMENT: tuple[tuple[str, str], ...] = (
    ("LANG", "C"),
    ("LC_ALL", "C"),
)

def canonical_git_environment(
    source: Mapping[str, str] | None = None,
    *,
    updates: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a host-independent Git environment for frozen patch operations."""

    environment = dict(os.environ if source is None else source)
    for key in tuple(environment):
        upper = key.upper()
        if upper.startswith("GIT_") or upper in {
            "DISPLAY",
            "GCM_INTERACTIVE",
            "SSH_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
        }:
            environment.pop(key, None)
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            **dict(CANONICAL_PATCH_ENVIRONMENT),
        }
    )
    if updates:
        environment.update(updates)
    return environment


def resolve_git_executable(source_path: str | None = None) -> str:
    """Resolve Git outside the current directory from absolute PATH entries."""

    allowed: list[Path] = []
    raw_path = os.environ.get("PATH", "") if source_path is None else source_path
    for raw in raw_path.split(os.pathsep):
        if not raw:
            continue
        path = Path(raw)
        if path.is_absolute():
            allowed.append(path.resolve())
    resolved = shutil.which("git", path=os.pathsep.join(str(path) for path in allowed))
    if resolved is None:
        raise FileNotFoundError("required Git command unavailable")
    executable = Path(resolved).resolve()
    if not executable.is_file() or executable.parent not in set(allowed):
        raise FileNotFoundError("required Git command unavailable")
    return str(executable)


def staged_patch_arguments() -> tuple[str, ...]:
    return ("diff", "--cached", *CANONICAL_PATCH_DIFF_OPTIONS)


def tree_patch_arguments(
    base: str,
    target: str,
    paths: Sequence[str],
) -> tuple[str, ...]:
    return (
        "diff",
        *CANONICAL_PATCH_DIFF_OPTIONS,
        base,
        target,
        "--",
        *paths,
    )
