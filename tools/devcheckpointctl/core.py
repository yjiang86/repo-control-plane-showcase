from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import tempfile
from typing import Any, Callable, Sequence
import uuid

from tools.frozenpatch import (
    CANONICAL_PATCH_DIFF_OPTIONS,
    CANONICAL_PATCH_GIT_CONFIG,
    canonical_git_environment,
    resolve_git_executable,
    tree_patch_arguments,
)
from tools.leasectl.core import (
    LockCoordinator,
    LockError,
    MAX_GIT_MUTATION_TTL_SECONDS,
)
from . import __version__


PROTOCOL = "development_checkpoint"
SCHEMA_VERSION = 1
ACTIVITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
OID_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ZERO_OID = "0" * 40
MAX_PATHS = 256
MAX_PATH_BYTES = 65536
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class CheckpointError(RuntimeError):
    def __init__(self, reason_code: str, detail: str):
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True)
class FreezeRequest:
    repo_root: Path
    activity: str
    label: str
    owner: str
    task: str
    paths: tuple[str, ...]
    expected_subject_sha256: str | None = None


@dataclass(frozen=True)
class ExportRequest:
    repo_root: Path
    activity: str
    output: Path


@dataclass(frozen=True)
class RepositoryState:
    head: str
    branch: str
    status_sha256: str
    index_sha256: str


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _safe_line(value: str, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise CheckpointError("INPUT_INVALID", f"{label} must be one bounded line")
    return value.strip()


def _activity(value: str) -> str:
    value = _safe_line(value, "activity", maximum=64)
    if not ACTIVITY_RE.fullmatch(value) or value.lower().endswith(".lock"):
        raise CheckpointError("INPUT_INVALID", "activity is not ref-safe")
    return value


def _absolute_repo(path: Path) -> Path:
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise CheckpointError("INPUT_INVALID", "repo root must be an absolute local path")
    try:
        _reject_reparse_ancestors(path)
        root = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise CheckpointError("INPUT_INVALID", "repo root does not exist") from error
    if not root.is_dir():
        raise CheckpointError("INPUT_INVALID", "repo root must be a directory")
    observed = _git(root, ("rev-parse", "--show-toplevel")).decode("utf-8").strip()
    try:
        observed_root = Path(observed).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise CheckpointError("REPOSITORY_INVALID", "cannot resolve Git top level") from error
    if os.path.normcase(str(observed_root)) != os.path.normcase(str(root)):
        raise CheckpointError("REPOSITORY_INVALID", "repo root must be the Git top level")
    return root


def _reject_reparse_ancestors(path: Path, *, stop: Path | None = None) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CheckpointError("PATH_SET_INVALID", "cannot inspect path ancestors") from error
        else:
            if current.is_symlink() or (
                os.name == "nt"
                and getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise CheckpointError("PATH_REPARSE_REJECTED", "path contains a reparse ancestor")
        if current == stop or current.parent == current:
            break
        current = current.parent


def _git_executable() -> str:
    try:
        return resolve_git_executable()
    except (OSError, RuntimeError) as error:
        raise CheckpointError(
            "GIT_COMMAND_FAILED", "required Git command unavailable"
        ) from error


def _git_environment(index_file: Path | None = None) -> dict[str, str]:
    environment = canonical_git_environment()
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_AUTHOR_NAME": "devcheckpointctl",
            "GIT_AUTHOR_EMAIL": "devcheckpointctl@example.invalid",
            "GIT_COMMITTER_NAME": "devcheckpointctl",
            "GIT_COMMITTER_EMAIL": "devcheckpointctl@example.invalid",
        }
    )
    pairs = {
        "core.hooksPath": os.devnull,
        "core.fsmonitor": "false",
        "core.untrackedCache": "false",
        "credential.helper": "",
        "core.askPass": "",
        "gc.auto": "0",
        "maintenance.auto": "false",
        **dict(CANONICAL_PATCH_GIT_CONFIG),
    }
    environment["GIT_CONFIG_COUNT"] = str(len(pairs))
    for index, (key, value) in enumerate(pairs.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    if index_file is not None:
        environment["GIT_INDEX_FILE"] = str(index_file)
    return environment


def _arguments_allowed(arguments: tuple[str, ...], ref: str | None = None) -> bool:
    if arguments in {
        ("rev-parse", "--show-toplevel"),
        ("rev-parse", "HEAD"),
        ("rev-parse", "HEAD^{tree}"),
        ("rev-parse", "--git-path", "index"),
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all"),
        ("write-tree",),
    }:
        return True
    if arguments == (
        "for-each-ref",
        "--format=%(refname) %(objectname)",
        "refs/codex/dev-checkpoints/",
    ):
        return True
    if len(arguments) == 4 and arguments[:3] == ("rev-parse", "--verify", "--quiet"):
        return ref is not None and arguments[3] == ref
    if len(arguments) == 2 and arguments[0] == "read-tree":
        return bool(re.fullmatch(r"[0-9a-f]{40}\^\{tree\}", arguments[1]))
    if arguments == ("hash-object", "-w", "--stdin"):
        return True
    if len(arguments) == 4 and arguments[:3] == ("update-index", "--force-remove", "--"):
        return True
    if len(arguments) == 4 and arguments[:3] == ("update-index", "--add", "--cacheinfo"):
        parts = arguments[3].split(",", 2)
        return (
            len(parts) == 3
            and parts[0] in {"100644", "100755"}
            and bool(OID_RE.fullmatch(parts[1]))
        )
    if len(arguments) == 5 and arguments[:2] == ("ls-tree", "-z"):
        return bool(OID_RE.fullmatch(arguments[2])) and arguments[3] == "--"
    if len(arguments) == 4 and arguments[0] == "commit-tree" and arguments[2] == "-p":
        return bool(OID_RE.fullmatch(arguments[1])) and bool(OID_RE.fullmatch(arguments[3]))
    if len(arguments) == 4 and arguments[0] == "update-ref":
        return ref is not None and arguments[1] == ref and all(
            OID_RE.fullmatch(value) for value in arguments[2:]
        )
    if len(arguments) == 4 and arguments[:3] == ("show", "-s", "--format=%T"):
        return bool(OID_RE.fullmatch(arguments[3]))
    if len(arguments) == 4 and arguments[:3] == ("show", "-s", "--format=%B"):
        return bool(OID_RE.fullmatch(arguments[3]))
    if len(arguments) == 6 and arguments[:4] == (
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
    ):
        return bool(OID_RE.fullmatch(arguments[4])) and bool(OID_RE.fullmatch(arguments[5]))
    if len(arguments) == 3 and arguments[:2] == ("rev-list", "--count"):
        pair = arguments[2].split("..", 1)
        return len(pair) == 2 and all(OID_RE.fullmatch(value) for value in pair)
    patch_prefix = ("diff", *CANONICAL_PATCH_DIFF_OPTIONS)
    if len(arguments) >= len(patch_prefix) + 3 and arguments[: len(patch_prefix)] == patch_prefix:
        base_index = len(patch_prefix)
        if not (
            OID_RE.fullmatch(arguments[base_index])
            and OID_RE.fullmatch(arguments[base_index + 1])
            and arguments[base_index + 2] == "--"
            and len(arguments) > base_index + 3
        ):
            return False
        try:
            normalized = _normalize_paths(arguments[base_index + 3 :])
        except CheckpointError:
            return False
        return tuple(arguments[base_index + 3 :]) == normalized
    return False


def _git(
    repo: Path,
    arguments: tuple[str, ...],
    *,
    index_file: Path | None = None,
    input_bytes: bytes | None = None,
    input_path: Path | None = None,
    ref: str | None = None,
    allow_missing: bool = False,
) -> bytes:
    if not _arguments_allowed(arguments, ref):
        raise CheckpointError("GIT_COMMAND_REJECTED", "Git command is outside the allowlist")
    if input_bytes is not None and input_path is not None:
        raise CheckpointError("GIT_COMMAND_REJECTED", "Git command has conflicting input sources")
    command = [
        _git_executable(),
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "credential.helper=",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-C",
        str(repo),
        *arguments,
    ]
    input_handle = None
    try:
        if input_path is not None:
            input_handle = input_path.open("rb")
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdin=(
                input_handle
                if input_handle is not None
                else subprocess.DEVNULL if input_bytes is None else None
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
            env=_git_environment(index_file),
            cwd=Path(tempfile.gettempdir()),
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckpointError("GIT_COMMAND_FAILED", "required Git command unavailable") from error
    finally:
        if input_handle is not None:
            input_handle.close()
    if completed.returncode != 0:
        if allow_missing and completed.returncode == 1:
            return b""
        raise CheckpointError(
            "GIT_COMMAND_FAILED",
            f"Git command exited {completed.returncode}",
        )
    return completed.stdout


def _repository_state(repo: Path, *, include_worktree_status: bool = True) -> RepositoryState:
    head = _git(repo, ("rev-parse", "HEAD")).decode("ascii").strip()
    if not OID_RE.fullmatch(head):
        raise CheckpointError("REPOSITORY_INVALID", "HEAD identity is invalid")
    branch = _git(repo, ("symbolic-ref", "--quiet", "--short", "HEAD")).decode(
        "utf-8"
    ).strip()
    status = _git(
        repo,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all"),
    ) if include_worktree_status else b""
    index_raw = _git(repo, ("rev-parse", "--git-path", "index")).decode("utf-8").strip()
    index_path = Path(index_raw)
    if not index_path.is_absolute():
        index_path = repo / index_path
    try:
        index_bytes = index_path.read_bytes() if index_path.exists() else b""
    except OSError as error:
        raise CheckpointError("REPOSITORY_INVALID", "cannot read canonical index") from error
    return RepositoryState(
        head=head,
        branch=branch,
        status_sha256=sha256_bytes(status),
        index_sha256=sha256_bytes(index_bytes),
    )


def _normalize_paths(values: Sequence[str]) -> tuple[str, ...]:
    if not values:
        return ()
    normalized: list[str] = []
    for raw in values:
        if not isinstance(raw, str) or not raw or any(
            character in raw for character in ("\x00", "\r", "\n")
        ):
            raise CheckpointError("PATH_SET_INVALID", "checkpoint path is invalid")
        value = raw.replace("\\", "/")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0].lower() == ".git"
            or value.endswith("/")
        ):
            raise CheckpointError("PATH_SET_INVALID", "checkpoint paths must be exact repo files")
        normalized.append(path.as_posix())
    unique = tuple(sorted(set(normalized)))
    folded = {os.path.normcase(path) for path in normalized}
    if len(unique) != len(normalized) or len(folded) != len(normalized):
        raise CheckpointError("PATH_SET_INVALID", "checkpoint paths must be unique")
    if len(unique) > MAX_PATHS or sum(len(path.encode("utf-8")) for path in unique) > MAX_PATH_BYTES:
        raise CheckpointError("PATH_SET_INVALID", "checkpoint path set is too large")
    return unique


def _path_set_sha256(paths: tuple[str, ...]) -> str:
    return sha256_bytes(canonical_json_bytes(list(paths)))


def _ref(activity: str) -> str:
    return f"refs/codex/dev-checkpoints/{activity}"


def _resolve_ref(repo: Path, ref: str) -> str | None:
    raw = _git(repo, ("rev-parse", "--verify", "--quiet", ref), ref=ref, allow_missing=True)
    if not raw:
        return None
    value = raw.decode("ascii").strip()
    if not OID_RE.fullmatch(value):
        raise CheckpointError("CHECKPOINT_REF_INVALID", "checkpoint ref identity is invalid")
    return value


def _commit_metadata(repo: Path, commit: str) -> dict[str, Any]:
    raw = _git(repo, ("show", "-s", "--format=%B", commit))
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint metadata is invalid") from error
    required_keys = {
        "activity",
        "base_head",
        "checkpoint_label",
        "path_set",
        "path_set_sha256",
        "protocol",
        "schema_version",
        "owner",
        "task",
        "tool_version",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required_keys
    ):
        raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint metadata is not closed")
    paths = value.get("path_set")
    if (
        value.get("protocol") != PROTOCOL
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value["owner"], str)
        or not isinstance(value["task"], str)
        or not isinstance(value["tool_version"], str)
        or not isinstance(paths, list)
        or not all(isinstance(path, str) for path in paths)
    ):
        raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint metadata is inconsistent")
    normalized = _normalize_paths(paths)
    if list(normalized) != paths or value.get("path_set_sha256") != _path_set_sha256(normalized):
        raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint path identity is invalid")
    if not OID_RE.fullmatch(str(value.get("base_head", ""))):
        raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint base identity is invalid")
    _safe_line(value["owner"], "checkpoint owner", maximum=128)
    _safe_line(value["task"], "checkpoint task", maximum=256)
    _safe_line(value["tool_version"], "checkpoint tool version", maximum=64)
    return value


def _regular_file(path: Path, repo: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise CheckpointError("PATH_SET_INVALID", "cannot inspect checkpoint path") from error
    if path.is_symlink() or not path.is_file():
        raise CheckpointError("PATH_SET_INVALID", "checkpoint paths must be regular files")
    if os.name == "nt" and getattr(metadata, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise CheckpointError("PATH_REPARSE_REJECTED", "checkpoint path is a reparse point")
    _reject_reparse_ancestors(path, stop=repo)
    try:
        resolved = path.resolve(strict=True)
        if os.path.commonpath((os.path.normcase(str(resolved)), os.path.normcase(str(repo)))) != os.path.normcase(str(repo)):
            raise CheckpointError("PATH_SET_INVALID", "checkpoint path escapes repo root")
    except (OSError, RuntimeError, ValueError) as error:
        raise CheckpointError("PATH_SET_INVALID", "checkpoint path escapes repo root") from error
    return True


def _base_entry(repo: Path, base_head: str, relative: str) -> tuple[str, str, str] | None:
    raw = _git(repo, ("ls-tree", "-z", base_head, "--", relative))
    if not raw:
        return None
    try:
        header, observed = raw.rstrip(b"\0").split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ", 2)
        observed_path = observed.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise CheckpointError("PATH_SET_INVALID", "cannot parse base path identity") from error
    if observed_path != relative or not OID_RE.fullmatch(oid):
        raise CheckpointError("PATH_SET_INVALID", "cannot bind exact base path identity")
    return mode, kind, oid


def _worktree_mode(absolute: Path, base_mode: str, *, platform_name: str = os.name) -> str:
    if platform_name == "nt":
        return base_mode
    try:
        mode = absolute.stat().st_mode
    except OSError as error:
        raise CheckpointError("PATH_SET_INVALID", "cannot inspect checkpoint file mode") from error
    return "100755" if mode & stat.S_IXUSR else "100644"


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _capture_regular_file(source: Path, repo: Path, destination: Path | None) -> tuple[int, str]:
    _regular_file(source, repo)
    try:
        before = source.lstat()
        digest = hashlib.sha256()
        size = 0
        with source.open("rb") as reader, (destination.open("xb") if destination is not None else nullcontext()) as writer:
            opened = os.fstat(reader.fileno())
            if not stat.S_ISREG(opened.st_mode) or (
                os.name == "nt"
                and getattr(opened, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise CheckpointError(
                    "PATH_REPARSE_REJECTED",
                    "checkpoint path changed before capture",
                )
            if _stat_identity(before) != _stat_identity(opened):
                raise CheckpointError(
                    "CANONICAL_STATE_CHANGED",
                    "checkpoint path identity changed before capture",
                )
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                if writer is not None:
                    writer.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            if writer is not None:
                writer.flush()
                os.fsync(writer.fileno())
        after = source.lstat()
    except CheckpointError:
        raise
    except OSError as error:
        raise CheckpointError("PATH_SET_INVALID", "cannot capture checkpoint path") from error
    _regular_file(source, repo)
    if _stat_identity(before) != _stat_identity(after) or size != after.st_size:
        raise CheckpointError(
            "CANONICAL_STATE_CHANGED",
            "checkpoint path changed during capture",
        )
    return size, digest.hexdigest()


def _assert_path_snapshots(
    repo: Path,
    base_head: str,
    snapshots: dict[str, tuple[bool, str | None, int | None, str | None]],
    *,
    heartbeat: Callable[[], None] | None = None,
) -> None:
    for relative, snapshot in snapshots.items():
        if heartbeat is not None:
            heartbeat()
        expected_exists, expected_mode, expected_size, expected_sha256 = snapshot
        absolute = repo / Path(*PurePosixPath(relative).parts)
        observed_exists = _regular_file(absolute, repo)
        if observed_exists != expected_exists:
            raise CheckpointError(
                "CANONICAL_STATE_CHANGED",
                "checkpoint path existence changed while checking checkpoint subject",
            )
        if not observed_exists:
            continue
        base_entry = _base_entry(repo, base_head, relative)
        base_mode = base_entry[0] if base_entry is not None else "100644"
        observed_mode = _worktree_mode(absolute, base_mode)
        observed_size, observed_sha256 = _capture_regular_file(
            absolute,
            repo,
            None,
        )
        if (
            observed_mode != expected_mode
            or observed_size != expected_size
            or observed_sha256 != expected_sha256
        ):
            raise CheckpointError(
                "CANONICAL_STATE_CHANGED",
                "checkpoint path bytes changed while checking checkpoint subject",
            )


def _build_tree(
    repo: Path,
    base_head: str,
    paths: tuple[str, ...],
    *,
    heartbeat: Callable[[], None] | None = None,
) -> tuple[str, list[str], dict[str, tuple[bool, str | None, int | None, str | None]]]:
    def beat() -> None:
        if heartbeat is not None:
            heartbeat()

    with tempfile.TemporaryDirectory(prefix="devcheckpointctl-") as temporary:
        index_file = Path(temporary) / "index"
        snapshots: dict[str, tuple[bool, str | None, int | None, str | None]] = {}
        beat()
        _git(repo, ("read-tree", f"{base_head}^{{tree}}"), index_file=index_file)
        for relative in paths:
            beat()
            absolute = repo / Path(*PurePosixPath(relative).parts)
            exists = _regular_file(absolute, repo)
            base_entry = _base_entry(repo, base_head, relative)
            if base_entry is not None:
                base_mode, kind, _oid = base_entry
                if kind != "blob" or base_mode not in {"100644", "100755"}:
                    raise CheckpointError("PATH_SET_INVALID", "checkpoint path has unsupported Git type")
                tracked = True
            else:
                base_mode = "100644"
                tracked = False
            if exists:
                mode = _worktree_mode(absolute, base_mode)
                beat()
                snapshot_file = Path(temporary) / f"source-{len(snapshots)}"
                snapshot_size, snapshot_sha256 = _capture_regular_file(
                    absolute,
                    repo,
                    snapshot_file,
                )
                oid = _git(
                    repo,
                    ("hash-object", "-w", "--stdin"),
                    input_path=snapshot_file,
                ).decode("ascii").strip()
                if not OID_RE.fullmatch(oid):
                    raise CheckpointError("CHECKPOINT_OBJECT_INVALID", "blob identity is invalid")
                snapshots[relative] = (True, mode, snapshot_size, snapshot_sha256)
                beat()
                _git(
                    repo,
                    ("update-index", "--add", "--cacheinfo", f"{mode},{oid},{relative}"),
                    index_file=index_file,
                )
            elif tracked:
                snapshots[relative] = (False, None, None, None)
                _git(
                    repo,
                    ("update-index", "--force-remove", "--", relative),
                    index_file=index_file,
                )
            else:
                raise CheckpointError("PATH_SET_INVALID", "checkpoint path is absent from base and worktree")
        # Re-read every selected path before publishing the alternate-index tree.
        # This catches a file that changed and reverted while the first pass was
        # sampling a multi-file checkpoint, even when porcelain returns to its
        # original identity.
        _assert_path_snapshots(
            repo,
            base_head,
            snapshots,
            heartbeat=heartbeat,
        )
        beat()
        tree = _git(repo, ("write-tree",), index_file=index_file).decode("ascii").strip()
    if not OID_RE.fullmatch(tree):
        raise CheckpointError("CHECKPOINT_OBJECT_INVALID", "tree identity is invalid")
    changed = sorted(
        line
        for line in _git(
            repo,
            ("diff-tree", "--no-commit-id", "--name-only", "-r", base_head, tree),
        ).decode("utf-8").splitlines()
        if line
    )
    if not set(changed).issubset(paths):
        raise CheckpointError("CHECKPOINT_CLOSED_SET_MISMATCH", "checkpoint contains an extra path")
    return tree, changed, snapshots


def _subject_sha256(
    base_head: str,
    paths: tuple[str, ...],
    snapshots: dict[str, tuple[bool, str | None, int | None, str | None]],
) -> str:
    return sha256_bytes(canonical_json_bytes({
        "base_head": base_head,
        "paths": [{"path": path, "snapshot": snapshots[path]} for path in paths],
    }))


def observe_subject(repo_root: Path, paths: Sequence[str]) -> dict[str, Any]:
    """Read the identity to bind before releasing PATH; this does not preserve bytes."""
    repo = _absolute_repo(repo_root)
    normalized = _normalize_paths(paths)
    if not normalized:
        raise CheckpointError("PATH_SET_REQUIRED", "subject requires exact paths")
    before = _repository_state(repo, include_worktree_status=False)
    snapshots: dict[str, tuple[bool, str | None, int | None, str | None]] = {}
    for relative in normalized:
        absolute = repo / Path(*PurePosixPath(relative).parts)
        exists = _regular_file(absolute, repo)
        entry = _base_entry(repo, before.head, relative)
        if entry is not None:
            base_mode, kind, _oid = entry
            if kind != "blob" or base_mode not in {"100644", "100755"}:
                raise CheckpointError("PATH_SET_INVALID", "checkpoint path has unsupported Git type")
        else:
            base_mode = "100644"
        if exists:
            mode = _worktree_mode(absolute, base_mode)
            size, digest = _capture_regular_file(
                absolute, repo, None,
            )
            snapshots[relative] = (True, mode, size, digest)
        elif entry is not None:
            snapshots[relative] = (False, None, None, None)
        else:
            raise CheckpointError("PATH_SET_INVALID", "checkpoint path is absent from base and worktree")
    _assert_path_snapshots(repo, before.head, snapshots)
    if _repository_state(repo, include_worktree_status=False) != before:
        raise CheckpointError("CANONICAL_STATE_CHANGED", "repository changed while observing subject")
    return {
        "status": "OBSERVED",
        "base_head": before.head,
        "path_set": list(normalized),
        "path_set_sha256": _path_set_sha256(normalized),
        "path_snapshots": [
            {"path": path, "exists": row[0], "mode": row[1], "size": row[2], "sha256": row[3]}
            for path, row in snapshots.items()
        ],
        "subject_sha256": _subject_sha256(before.head, normalized, snapshots),
    }


def _patch(repo: Path, base_head: str, checkpoint: str, paths: tuple[str, ...]) -> bytes:
    return _git(repo, tree_patch_arguments(base_head, checkpoint, paths))


def _validated_checkpoint(repo: Path, activity: str) -> tuple[str, dict[str, Any], str, tuple[str, ...]]:
    ref = _ref(activity)
    commit = _resolve_ref(repo, ref)
    if commit is None:
        raise CheckpointError("CHECKPOINT_NOT_FOUND", "development checkpoint does not exist")
    metadata = _commit_metadata(repo, commit)
    if metadata["activity"] != activity:
        raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint activity is inconsistent")
    tree = _git(repo, ("show", "-s", "--format=%T", commit)).decode("ascii").strip()
    if not OID_RE.fullmatch(tree):
        raise CheckpointError("CHECKPOINT_OBJECT_INVALID", "checkpoint tree is invalid")
    return commit, metadata, tree, tuple(metadata["path_set"])


def freeze_checkpoint(request: FreezeRequest) -> dict[str, Any]:
    repo = _absolute_repo(request.repo_root)
    activity = _activity(request.activity)
    label = _safe_line(request.label, "checkpoint label", maximum=256)
    owner = _safe_line(request.owner, "owner", maximum=128)
    task = _safe_line(request.task, "task", maximum=256)
    requested_paths = _normalize_paths(request.paths)
    expected = request.expected_subject_sha256
    if expected is not None and (not isinstance(expected, str) or not SHA256_RE.fullmatch(expected)):
        raise CheckpointError("INPUT_INVALID", "expected subject must be a lowercase SHA256")
    ref = _ref(activity)
    lock = LockCoordinator(repo)
    nonce = secrets.token_hex(32)
    lock_id = f"LOCK-devcheckpoint-{activity}-{uuid.uuid4().hex[:12]}"
    acquired = False
    result: dict[str, Any] | None = None
    try:
        initial = _repository_state(repo)
        lock.acquire(
            lock_kind="GIT_MUTATION_LOCK",
            task=task,
            owner=owner,
            ttl_seconds=MAX_GIT_MUTATION_TTL_SECONDS,
            nonce=nonce,
            lock_id=lock_id,
            base_head=initial.head,
        )
        acquired = True

        def heartbeat() -> None:
            try:
                lock.renew_active(
                    lock_id=lock_id,
                    owner=owner,
                    nonce=nonce,
                    ttl_seconds=MAX_GIT_MUTATION_TTL_SECONDS,
                    new_nonce=nonce,
                )
            except LockError as error:
                raise CheckpointError("GIT_MUTATION_LOCK_LOST", str(error)) from error

        heartbeat()
        before = _repository_state(repo)
        heartbeat()
        if before != initial:
            raise CheckpointError("CANONICAL_STATE_CHANGED", "repository changed before checkpoint lock")

        previous = _resolve_ref(repo, ref)
        heartbeat()
        if previous is None:
            if not requested_paths:
                raise CheckpointError("PATH_SET_REQUIRED", "first checkpoint requires exact paths")
            base_head = before.head
            paths = requested_paths
            parent = base_head
            previous_tree = None
        else:
            metadata = _commit_metadata(repo, previous)
            heartbeat()
            if metadata["activity"] != activity:
                raise CheckpointError("CHECKPOINT_METADATA_INVALID", "checkpoint activity is inconsistent")
            base_head = metadata["base_head"]
            paths = tuple(metadata["path_set"])
            if before.head != base_head:
                raise CheckpointError(
                    "BASE_HEAD_CHANGED",
                    "activity base HEAD changed; start a successor activity instead of rebasing history",
                )
            if requested_paths and requested_paths != paths:
                raise CheckpointError(
                    "PATH_SET_CHANGED",
                    "activity path set changed; start a successor activity instead of widening history",
                )
            parent = previous
            previous_tree = _git(repo, ("show", "-s", "--format=%T", previous)).decode(
                "ascii"
            ).strip()
            heartbeat()

        tree, changed, snapshots = _build_tree(repo, base_head, paths, heartbeat=heartbeat)
        subject_sha256 = _subject_sha256(base_head, paths, snapshots)
        if expected is not None and subject_sha256 != expected:
            raise CheckpointError(
                "EXPECTED_SUBJECT_MISMATCH",
                "captured subject differs from expected base/path/content identity",
            )
        if previous is None and tree == _git(repo, ("rev-parse", "HEAD^{tree}")).decode(
            "ascii"
        ).strip():
            result = {
                "activity": activity,
                "base_head": base_head,
                "branch": before.branch,
                "changed_paths": [],
                "checkpoint_commit": None,
                "checkpoint_ref": ref,
                "checkpoint_tree": tree,
                "path_set": list(paths),
                "path_set_sha256": _path_set_sha256(paths),
                "subject_sha256": subject_sha256,
                "expected_subject_bound": expected is not None,
                "status": "NO_CHANGE",
            }
            return result
        if previous_tree == tree:
            patch = _patch(repo, base_head, previous, paths)
            result = {
                "activity": activity,
                "base_head": base_head,
                "branch": before.branch,
                "changed_paths": changed,
                "checkpoint_commit": previous,
                "checkpoint_ref": ref,
                "checkpoint_tree": tree,
                "patch_bytes": len(patch),
                "patch_sha256": sha256_bytes(patch),
                "path_set": list(paths),
                "path_set_sha256": _path_set_sha256(paths),
                "subject_sha256": subject_sha256,
                "expected_subject_bound": expected is not None,
                "status": "UNCHANGED",
            }
            return result

        if _repository_state(repo) != before:
            raise CheckpointError("CANONICAL_STATE_CHANGED", "repository changed while building checkpoint")
        heartbeat()
        message = canonical_json_bytes(
            {
                "activity": activity,
                "base_head": base_head,
                "checkpoint_label": label,
                "owner": owner,
                "path_set": list(paths),
                "path_set_sha256": _path_set_sha256(paths),
                "protocol": PROTOCOL,
                "schema_version": SCHEMA_VERSION,
                "task": task,
                "tool_version": __version__,
            }
        )
        commit = _git(
            repo,
            ("commit-tree", tree, "-p", parent),
            input_bytes=message,
        ).decode("ascii").strip()
        if not OID_RE.fullmatch(commit):
            raise CheckpointError("CHECKPOINT_OBJECT_INVALID", "commit identity is invalid")
        heartbeat()
        patch = _patch(repo, base_head, commit, paths)
        depth = int(
            _git(repo, ("rev-list", "--count", f"{base_head}..{commit}")).decode(
                "ascii"
            ).strip()
        )
        prepared_result = {
            "activity": activity,
            "base_head": base_head,
            "branch": before.branch,
            "canonical_index_sha256": before.index_sha256,
            "canonical_status_sha256": before.status_sha256,
            "changed_paths": changed,
            "checkpoint_commit": commit,
            "checkpoint_depth": depth,
            "checkpoint_ref": ref,
            "checkpoint_tree": tree,
            "parent_checkpoint": previous,
            "patch_bytes": len(patch),
            "patch_sha256": sha256_bytes(patch),
            "path_set": list(paths),
            "path_set_sha256": _path_set_sha256(paths),
            "subject_sha256": subject_sha256,
            "expected_subject_bound": expected is not None,
            "status": "FROZEN",
        }
        if _repository_state(repo) != before:
            raise CheckpointError(
                "CANONICAL_STATE_CHANGED",
                "repository changed before checkpoint ref publication",
            )
        _assert_path_snapshots(
            repo,
            base_head,
            snapshots,
            heartbeat=heartbeat,
        )
        heartbeat()
        _git(repo, ("update-ref", ref, commit, previous or ZERO_OID), ref=ref)
        result = prepared_result
        return result
    except LockError as error:
        raise CheckpointError("GIT_MUTATION_LOCK_UNAVAILABLE", str(error)) from error
    finally:
        if acquired:
            try:
                lock.release(lock_id=lock_id, owner=owner, nonce=nonce)
            except LockError as error:
                raise CheckpointError("GIT_MUTATION_LOCK_RELEASE_FAILED", str(error)) from error


def inspect_checkpoint(repo_root: Path, activity_value: str) -> dict[str, Any]:
    repo = _absolute_repo(repo_root)
    activity = _activity(activity_value)
    commit, metadata, tree, paths = _validated_checkpoint(repo, activity)
    base_head = metadata["base_head"]
    changed = sorted(
        line
        for line in _git(
            repo,
            ("diff-tree", "--no-commit-id", "--name-only", "-r", base_head, commit),
        ).decode("utf-8").splitlines()
        if line
    )
    if not set(changed).issubset(paths):
        raise CheckpointError("CHECKPOINT_CLOSED_SET_MISMATCH", "checkpoint contains an extra path")
    patch = _patch(repo, base_head, commit, paths)
    current_head = _repository_state(repo).head
    return {
        "activity": activity,
        "base_head": base_head,
        "base_state": "CURRENT" if current_head == base_head else "MOVED",
        "changed_paths": changed,
        "checkpoint_commit": commit,
        "checkpoint_depth": int(
            _git(repo, ("rev-list", "--count", f"{base_head}..{commit}")).decode("ascii").strip()
        ),
        "checkpoint_label": metadata["checkpoint_label"],
        "checkpoint_ref": _ref(activity),
        "checkpoint_tree": tree,
        "current_head": current_head,
        "patch_bytes": len(patch),
        "patch_sha256": sha256_bytes(patch),
        "path_set": list(paths),
        "path_set_sha256": metadata["path_set_sha256"],
        "owner": metadata["owner"],
        "status": "EXACT",
        "task": metadata["task"],
        "tool_version": metadata["tool_version"],
    }


def list_checkpoints(repo_root: Path) -> dict[str, Any]:
    repo = _absolute_repo(repo_root)
    raw = _git(
        repo,
        (
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/codex/dev-checkpoints/",
        ),
    )
    items: list[dict[str, Any]] = []
    prefix = "refs/codex/dev-checkpoints/"
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        try:
            ref, observed_commit = line.split(" ", 1)
        except ValueError as error:
            raise CheckpointError("CHECKPOINT_REF_INVALID", "cannot parse checkpoint ref") from error
        if not ref.startswith(prefix):
            raise CheckpointError("CHECKPOINT_REF_INVALID", "checkpoint ref escaped namespace")
        activity = _activity(ref[len(prefix) :])
        commit, metadata, tree, paths = _validated_checkpoint(repo, activity)
        if commit != observed_commit:
            raise CheckpointError("CHECKPOINT_REF_INVALID", "checkpoint ref changed while listing")
        items.append(
            {
                "activity": activity,
                "base_head": metadata["base_head"],
                "checkpoint_commit": commit,
                "checkpoint_label": metadata["checkpoint_label"],
                "checkpoint_tree": tree,
                "path_count": len(paths),
                "owner": metadata["owner"],
                "task": metadata["task"],
                "tool_version": metadata["tool_version"],
            }
        )
    return {"checkpoints": items, "count": len(items), "status": "OK"}


def export_checkpoint(request: ExportRequest) -> dict[str, Any]:
    repo = _absolute_repo(request.repo_root)
    activity = _activity(request.activity)
    output = request.output
    if not output.is_absolute() or str(output).startswith(("\\\\", "//")):
        raise CheckpointError("INPUT_INVALID", "export output must be an absolute local path")
    try:
        _reject_reparse_ancestors(output.parent)
        target = output.resolve(strict=False)
        target.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise CheckpointError("INPUT_INVALID", "export parent does not exist") from error
    try:
        normalized_target = os.path.normcase(str(target))
        normalized_repo = os.path.normcase(str(repo))
        if os.path.commonpath((normalized_target, normalized_repo)) == normalized_repo:
            raise CheckpointError("EXPORT_TARGET_INVALID", "checkpoint export must be outside the repo")
    except ValueError:
        pass
    if target.exists():
        raise CheckpointError("EXPORT_TARGET_EXISTS", "checkpoint export is create-only")
    commit, metadata, _tree, paths = _validated_checkpoint(repo, activity)
    patch = _patch(repo, metadata["base_head"], commit, paths)
    try:
        with target.open("xb") as handle:
            handle.write(patch)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise CheckpointError("EXPORT_WRITE_FAILED", "cannot create checkpoint export") from error
    return {
        "activity": activity,
        "checkpoint_commit": commit,
        "output": str(target),
        "patch_bytes": len(patch),
        "patch_sha256": sha256_bytes(patch),
        "status": "EXPORTED",
    }
