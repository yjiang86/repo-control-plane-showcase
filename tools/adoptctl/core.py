from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Iterator
import uuid

import jsonschema
import yaml

from . import __version__ as CLIENT_VERSION
from tools.leasectl.core import LockCoordinator, LockError
from tools.leasectl import core as lock_core
from tools.topctl.cli import (
    build_render_lock,
    canonical_json_bytes,
    compose_render,
    sha256_bytes,
    validate_repo_config,
)


PACKAGE_FILE = "package.json"
PACKAGE_KIND = "leaf_first_adoption"
PACKAGE_SCHEMA_VERSION = 3
TARGET_PATHS = (
    ".toplayer/local/AGENTS.project.md",
    ".toplayer/repo.yaml",
    ".toplayer/render.lock.json",
    "AGENTS.md",
)
ROLLBACK_PATHS = (
    ".toplayer/render.lock.json",
    ".toplayer/repo.yaml",
    ".toplayer/local/AGENTS.project.md",
    "AGENTS.md",
)
ACKNOWLEDGEMENT = "HELD_UNDER_LEAF_POLICY"
JOURNAL_FILE = "apply.journal.jsonl"
RECEIPT_FILE = "apply.receipt.json"
DEFAULT_NETWORK_TIMEOUT_SECONDS = 120
MAX_NETWORK_TIMEOUT_SECONDS = 120
DEFAULT_PATH_LOCK_TTL_SECONDS = 900
DEFAULT_PUBLISH_RESERVE_SECONDS = 1800
MIN_PUBLISH_RESERVE_SECONDS = 900
MIN_FIRST_WRITE_BUDGET_SECONDS = 300
MAX_SCHEMA3_PUBLISH_TTL_SECONDS = 7200
SCHEMA3_ADAPTER_ID = "leaf_schema3_publish_registry_adapter"
SCHEMA3_ADAPTER_VERSION = "1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
CONTROL_RELEASE_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
WHOLE_SECOND_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_RUNTIME_STATE_TEMP_RE = re.compile(r"^state\.json\.tmp\.[1-9][0-9]*\.[0-9a-f]{32}$")

# This is deliberately process-local.  The released writer pins its Git binary
# before its first invocation and never authorizes a later basename or PATH
# lookup while the mutation broker is active.
_PINNED_GIT_EXECUTABLE: Path | None = None


class AdoptionError(ValueError):
    """A fail-closed first-adoption precondition or integrity failure."""


class ApplyOutcomeError(AdoptionError):
    result = "BLOCKED"


class AbortedPrewriteError(ApplyOutcomeError):
    """The live lock failed before any leaf mutation was attempted."""

    result = "ABORTED_PREWRITE"


class FailedRolledBackError(ApplyOutcomeError):
    """A write failed, but every reached target was CAS-restored."""

    result = "FAILED_ROLLED_BACK"


class PartialApplyError(ApplyOutcomeError):
    """Apply may have changed a leaf and safe rollback is no longer provable."""

    result = "PARTIAL_APPLY"


class LockContinuityError(PartialApplyError):
    """A strict renewal gap makes any target overwrite unsafe."""


class MutationAuditError(AdoptionError):
    """The in-process mutation gate rejected an out-of-closure operation."""


class PublicationVerificationError(AdoptionError):
    """A stable fail-closed reason from post-publication verification."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class LeafGate:
    identity: dict[str, Any]
    staged_index: dict[str, Any]
    target_preimages: list[dict[str, Any]]


@dataclass(frozen=True)
class ApplyEvidence:
    manifest: dict[str, Any]
    package_entries: list[dict[str, Any]]
    payloads: dict[str, bytes]
    prepared: dict[str, Any]
    journal_sha256: str
    receipt_sha256: str


def _canonical_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise AdoptionError(f"{label} must be a canonical repository-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AdoptionError(f"{label} must be a canonical repository-relative path")
    if path.as_posix() != value:
        raise AdoptionError(f"{label} must be a canonical repository-relative path")
    return value


def _is_redirect(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def _require_regular_file(path: Path, label: str) -> bytes:
    if _is_redirect(path) or not path.is_file():
        raise AdoptionError(f"{label} must be a regular non-redirected file")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise AdoptionError(f"{label} exceeds the 4 MiB safety limit")
    return path.read_bytes()


def _read_regular_bound(path: Path, label: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    """Read one regular file only after stable no-follow identity checks."""

    try:
        with path.open("rb") as handle:
            handle_before = os.fstat(handle.fileno())
            path_before = path.lstat()
            if (
                not stat.S_ISREG(handle_before.st_mode)
                or not stat.S_ISREG(path_before.st_mode)
                or bool(getattr(path_before, "st_file_attributes", 0) & 0x400)
                or not os.path.samestat(handle_before, path_before)
            ):
                raise AdoptionError(f"{label} must be a regular non-redirected file")
            chunks: list[bytes] = []
            size = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                if size > maximum:
                    raise AdoptionError(f"{label} exceeds the 4 MiB safety limit")
                chunks.append(chunk)
            handle_after = os.fstat(handle.fileno())
            path_after = path.lstat()
    except OSError as error:
        raise AdoptionError(f"{label} cannot be opened and identity-checked") from error
    if (
        not stat.S_ISREG(handle_after.st_mode)
        or not stat.S_ISREG(path_after.st_mode)
        or bool(getattr(path_after, "st_file_attributes", 0) & 0x400)
        or not os.path.samestat(handle_before, handle_after)
        or not os.path.samestat(handle_after, path_after)
        or not os.path.samestat(path_before, path_after)
    ):
        raise AdoptionError(f"{label} changed identity during read")
    return b"".join(chunks)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _within_lexical(path: Path, root: Path) -> bool:
    try:
        path.absolute().relative_to(root.absolute())
    except ValueError:
        return False
    return True


def _target_path(root: Path, logical_path: str) -> Path:
    logical_path = _canonical_path(logical_path, "target path")
    target = root / Path(*PurePosixPath(logical_path).parts)
    if not _within(target, root):
        raise AdoptionError("target path escapes leaf root")
    return target


def _assert_no_redirected_ancestors(root: Path, target: Path) -> None:
    if not _within_lexical(target, root):
        raise AdoptionError("target path escapes leaf root")
    cursor = root
    if _is_redirect(cursor) or not cursor.is_dir():
        raise AdoptionError("leaf root is redirected or not a directory")
    for part in target.relative_to(root).parts[:-1]:
        cursor = cursor / part
        if cursor.exists() and (_is_redirect(cursor) or not cursor.is_dir()):
            raise AdoptionError("target parent is redirected or not a directory")


@contextmanager
def _pinned_ancestors(root: Path, target: Path) -> Iterator[None]:
    """Pin existing lexical ancestors against replacement during one operation."""

    _assert_no_redirected_ancestors(root, target)
    handles: list[int] = []
    close_handle: Any = None
    try:
        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            create_file.restype = ctypes.c_void_p
            get_attributes = kernel32.GetFileAttributesW
            get_attributes.argtypes = [ctypes.c_wchar_p]
            get_attributes.restype = ctypes.c_uint32
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [ctypes.c_void_p]
            close_handle.restype = ctypes.c_int
            invalid = ctypes.c_void_p(-1).value
            cursor = root
            for part in ("", *target.relative_to(root).parts[:-1]):
                if part:
                    cursor = cursor / part
                if not cursor.exists():
                    break
                handle = create_file(
                    str(cursor),
                    0x00000080,
                    0x00000001 | 0x00000002,
                    None,
                    3,
                    0x02000000 | 0x00200000,
                    None,
                )
                if handle == invalid:
                    raise AdoptionError("cannot pin path ancestor against replacement")
                handles.append(handle)
                attributes = get_attributes(str(cursor))
                if attributes == 0xFFFFFFFF or attributes & 0x400:
                    raise AdoptionError("pinned path ancestor is a reparse point")
        yield
    finally:
        if os.name == "nt":
            for handle in reversed(handles):
                if close_handle is None or not close_handle(handle):
                    raise AdoptionError("cannot close pinned path ancestor")


def _network_timeout(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_NETWORK_TIMEOUT_SECONDS:
        raise AdoptionError(
            f"network_timeout_seconds must be between 1 and {MAX_NETWORK_TIMEOUT_SECONDS}"
        )
    return value


def _pinned_git_executable() -> Path:
    """Return the one regular, non-redirected Git executable for this process."""

    global _PINNED_GIT_EXECUTABLE
    if _PINNED_GIT_EXECUTABLE is not None:
        return _PINNED_GIT_EXECUTABLE
    located = shutil.which("git") or shutil.which("git.exe")
    if not located:
        raise AdoptionError("Git executable is unavailable")
    candidate = Path(located).absolute()
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise AdoptionError("Git executable cannot be identity-checked") from error
    if (
        _is_redirect(candidate)
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(candidate, os.X_OK)
    ):
        raise AdoptionError("Git executable must be an absolute regular non-redirected file")
    _PINNED_GIT_EXECUTABLE = candidate
    return candidate


def _sanitized_git_environment() -> dict[str, str]:
    """Build the only environment accepted by brokered read-only Git calls.

    The allowlist intentionally starts from no inherited variables.  It keeps
    only host values needed for normal SSH-agent/key discovery and the minimum
    operating-system process bootstrap, then supplies a fixed search path
    derived from the pinned executable rather than caller PATH.
    """

    executable = _pinned_git_executable()
    path_parts = [str(executable.parent)]
    if os.name == "nt":
        install_root = executable.parent.parent
        path_parts.extend(
            [str(install_root / "usr" / "bin"), str(install_root / "bin")]
        )
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if system_root:
            path_parts.append(str(Path(system_root) / "System32"))
    else:
        path_parts.extend(part for part in os.defpath.split(os.pathsep) if part)
    unique_parts: list[str] = []
    for part in path_parts:
        if part not in unique_parts:
            unique_parts.append(part)
    result = {
        "GIT_OPTIONAL_LOCKS": "0",
        "PATH": os.pathsep.join(unique_parts),
    }
    preserved = (
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERPROFILE",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    )
    for key in preserved:
        value = os.environ.get(key)
        if isinstance(value, str) and value:
            result[key] = value
    return {key: result[key] for key in sorted(result)}


def _git_environment_sha256(environment: dict[str, str]) -> str:
    return sha256_bytes(canonical_json_bytes(environment))


def _run_git(root: Path, arguments: tuple[str, ...], timeout_seconds: int) -> subprocess.CompletedProcess[bytes]:
    executable = _pinned_git_executable()
    try:
        return subprocess.run(
            [str(executable), *arguments],
            executable=str(executable),
            cwd=str(root.absolute()),
            check=False,
            capture_output=True,
            text=False,
            env=_sanitized_git_environment(),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise AdoptionError(
            f"git {' '.join(arguments)} timed out after {timeout_seconds} seconds"
        ) from error


def _git(root: Path, *arguments: str, timeout_seconds: int = 60) -> str:
    try:
        completed = _run_git(root, tuple(arguments), timeout_seconds)
    except AdoptionError:
        raise
    if completed.returncode:
        message = completed.stderr.decode("utf-8", "replace").strip()
        raise AdoptionError(f"git {' '.join(arguments)} failed: {message}")
    return completed.stdout.decode("utf-8", "strict").strip()


def _git_bytes(root: Path, *arguments: str, timeout_seconds: int = 60) -> bytes:
    try:
        completed = _run_git(root, tuple(arguments), timeout_seconds)
    except AdoptionError:
        raise
    if completed.returncode:
        message = completed.stderr.decode("utf-8", "replace").strip()
        raise AdoptionError(f"git {' '.join(arguments)} failed: {message}")
    return completed.stdout


def _git_root(leaf_root: Path) -> Path:
    root = Path(_git(leaf_root, "rev-parse", "--show-toplevel")).resolve()
    if root != leaf_root.resolve():
        raise AdoptionError("--leaf-root must be the exact Git worktree root")
    return root


def _worktree_count(root: Path) -> int:
    return sum(
        1
        for line in _git(root, "worktree", "list", "--porcelain").splitlines()
        if line.startswith("worktree ")
    )


def _remote(root: Path) -> str:
    fetch = _git(root, "remote", "get-url", "origin")
    push = _git(root, "remote", "get-url", "--push", "origin")
    if fetch != push:
        raise AdoptionError("origin fetch and push remotes differ")
    return fetch


def _remote_main(root: Path, head: str, network_timeout_seconds: int) -> str:
    timeout = _network_timeout(network_timeout_seconds)
    output = _git(
        root,
        "ls-remote",
        "origin",
        "refs/heads/main",
        timeout_seconds=timeout,
    )
    rows = [line.split("\t") for line in output.splitlines() if line]
    if len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != "refs/heads/main":
        raise AdoptionError("origin main identity is absent or ambiguous")
    remote_main = rows[0][0]
    if not OID_RE.fullmatch(remote_main) or remote_main != head:
        raise AdoptionError("leaf HEAD must exactly equal live origin/main")
    return remote_main


def _parse_status_payload(raw: bytes) -> list[dict[str, Any]]:
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    result: list[dict[str, Any]] = []
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < 4 or record[2:3] != b" ":
            raise AdoptionError("Git status output is malformed")
        try:
            status = record[:2].decode("ascii")
            path = record[3:].decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise AdoptionError("Git status path is not UTF-8") from error
        if status == "??" and path.endswith("/"):
            path = path[:-1]
        paths = [_canonical_path(path, "Git status path")]
        if "R" in status or "C" in status:
            index += 1
            if index >= len(records):
                raise AdoptionError("Git rename status is truncated")
            try:
                paths.append(_canonical_path(records[index].decode("utf-8", "strict"), "Git status path"))
            except UnicodeDecodeError as error:
                raise AdoptionError("Git status path is not UTF-8") from error
        result.append({"status": status, "paths": paths})
        index += 1
    return result


def _parse_status(root: Path) -> list[dict[str, Any]]:
    """Use Git's semantic status only; never recursively read dirty content."""

    return _parse_status_payload(
        _git_bytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    )


def _static_leaf_identity(root: Path, network_timeout_seconds: int) -> dict[str, Any]:
    """Bind only the leaf identities that are meaningful for this apply.

    This deliberately does not invoke ``git status``.  A dirty worktree can
    contain another manager's arbitrarily large, concurrently changing
    non-closed tree; enumerating it would reintroduce dev.17's timeout and
    fake-global-equality failure mode.
    """

    _git_root(root)
    if _git(root, "symbolic-ref", "--quiet", "--short", "HEAD") != "main":
        raise AdoptionError("leaf must be on exact branch main")
    if _worktree_count(root) != 1:
        raise AdoptionError("leaf must have exactly one worktree")
    origin = _remote(root)
    head = _git(root, "rev-parse", "HEAD")
    identity = {
        "branch": "main",
        "worktree_count": 1,
        "head": head,
        "remote_main": _remote_main(root, head, network_timeout_seconds),
        "tree": _git(root, "rev-parse", "HEAD^{tree}"),
        "origin_sha256": sha256_bytes(origin.encode("utf-8")),
    }
    return identity


def _staged_index_identity(root: Path) -> dict[str, Any]:
    raw = _git_bytes(root, "diff", "--cached", "--raw", "-z", "--full-index")
    return {"clean": not bool(raw), "sha256": sha256_bytes(raw)}


def _target_identity(root: Path, logical_path: str) -> dict[str, Any]:
    target = _target_path(root, logical_path)
    _assert_no_redirected_ancestors(root, target)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return {"path": logical_path, "state": "ABSENT"}
    if _is_redirect(target) or not stat.S_ISREG(metadata.st_mode):
        raise AdoptionError(f"target {logical_path} must be a regular non-redirected file")
    payload = _read_regular_bound(target, f"target {logical_path}")
    return {
        "path": logical_path,
        "state": "PRESENT",
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _preimages(root: Path) -> list[dict[str, Any]]:
    return [_target_identity(root, logical_path) for logical_path in TARGET_PATHS]


def _assert_no_partial_bootstrap_contamination(root: Path) -> None:
    """A first adoption cannot inherit an unbound .toplayer scaffold."""

    for logical in (".toplayer", ".toplayer/local"):
        path = root / Path(*PurePosixPath(logical).parts)
        if os.path.lexists(path):
            raise AdoptionError("first adoption rejects partial bootstrap directory contamination")


def _assert_overlay_preimage_binding(manifest: dict[str, Any], payloads: dict[str, bytes]) -> None:
    try:
        agents = manifest["leaf"]["target_preimages"][3]
    except (KeyError, IndexError, TypeError) as error:
        raise AdoptionError("package AGENTS preimage binding is invalid") from error
    overlay = payloads[".toplayer/local/AGENTS.project.md"]
    if (
        agents.get("state") != "PRESENT"
        or agents.get("bytes") != len(overlay)
        or agents.get("sha256") != sha256_bytes(overlay)
    ):
        raise AdoptionError("package overlay does not exactly bind the AGENTS preimage")


def _validate_temp_directory(path: Path, label: str, *repository_roots: Path) -> Path:
    path = path.absolute()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if path == temp_root or not _within_lexical(path, temp_root):
        raise AdoptionError(f"{label} must be below the system temporary root")
    if any(_within(path, root.resolve()) for root in repository_roots):
        raise AdoptionError(f"{label} must remain outside repositories")
    cursor = temp_root
    for part in path.relative_to(temp_root).parts:
        cursor = cursor / part
        if _is_redirect(cursor):
            raise AdoptionError(f"{label} is redirected")
    if not path.is_dir() or _is_redirect(path) or any(path.iterdir()):
        raise AdoptionError(f"{label} must already exist and be empty")
    return path


def _validate_temp_package_dir(path: Path, *repository_roots: Path) -> Path:
    return _validate_temp_directory(path, "package directory", *repository_roots)


def _validate_journal_dir(path: Path, *repository_roots: Path) -> Path:
    return _validate_temp_directory(path, "journal directory", *repository_roots)


def _registry_remote(control_plane: Path, repo_id: str) -> str:
    document = yaml.safe_load((control_plane / "registry" / "repos.yaml").read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("repositories"), list):
        raise AdoptionError("repository registry is invalid")
    matches = [
        entry
        for entry in document["repositories"]
        if isinstance(entry, dict) and entry.get("repo_id") == repo_id
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("remote"), str):
        raise AdoptionError("candidate repo_id must have one exact registry remote")
    return matches[0]["remote"]


def _validate_candidate(candidate: Path, control_plane: Path) -> tuple[dict[str, Any], bytes]:
    payload = _require_regular_file(candidate, "repo.yaml candidate")
    try:
        value = yaml.safe_load(payload.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise AdoptionError("repo.yaml candidate is invalid YAML") from error
    if not isinstance(value, dict):
        raise AdoptionError("repo.yaml candidate must contain a YAML object")
    validate_repo_config(value)
    if value["local_overlay"] != {"agents": ".toplayer/local/AGENTS.project.md"}:
        raise AdoptionError("first adoption requires the canonical local overlay path")
    if value["control_plane"]["repo_id"] != "repo-control-plane":
        raise AdoptionError("repo.yaml candidate has invalid control-plane identity")
    if value["control_plane"]["remote"] != _remote(control_plane):
        raise AdoptionError("repo.yaml candidate control-plane remote mismatch")
    return value, payload


def runtime_root() -> Path:
    """Return the root owning the modules imported by this process."""

    return Path(__file__).resolve().parents[2]


def _control_release_version(control_plane: Path) -> str:
    payload = _require_regular_file(control_plane / "VERSION", "control release VERSION")
    try:
        text = payload.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise AdoptionError("control release VERSION must be ASCII") from error
    if payload != (text + "\n").encode("ascii") or not CONTROL_RELEASE_RE.fullmatch(text):
        raise AdoptionError("control release VERSION is invalid")
    return text


def _assert_runtime_isolated(control_plane: Path, leaf_root: Path, manifest_path: Path) -> None:
    runtime = runtime_root()
    manifest = manifest_path.resolve()
    for protected in (control_plane.resolve(), leaf_root.resolve()):
        if _within(runtime, protected) or _within(manifest, protected):
            raise AdoptionError("runtime and runtime manifest must remain outside control and leaf checkouts")


def _assert_clean_tagged_control(control_plane: Path) -> None:
    _git_root(control_plane)
    if _git(control_plane, "symbolic-ref", "--quiet", "--short", "HEAD") != "main":
        raise AdoptionError("control-plane checkout must be on exact branch main")
    if _worktree_count(control_plane) != 1 or _parse_status(control_plane):
        raise AdoptionError("control-plane checkout must be clean with one worktree")
    tag_ref = f"refs/tags/v{_control_release_version(control_plane)}"
    if (
        _git(control_plane, "cat-file", "-t", tag_ref) != "tag"
        or _git(control_plane, "rev-parse", "HEAD")
        != _git(control_plane, "rev-parse", f"{tag_ref}^{{}}")
    ):
        raise AdoptionError("control-plane checkout is not at the exact annotated release")


def _validate_runtime_manifest(
    manifest_path: Path, control_plane: Path | None = None
) -> dict[str, Any]:
    payload = _require_regular_file(manifest_path, "runtime manifest")
    if control_plane is not None:
        _assert_clean_tagged_control(control_plane)
        released = _require_regular_file(
            control_plane / "integrations" / "leaf-first-adoption" / "runtime-manifest.json",
            "released runtime manifest",
        )
        if payload != released:
            raise AdoptionError("external runtime manifest bytes differ from the exact released manifest")
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdoptionError("runtime manifest is invalid JSON") from error
    required = {"schema_version", "integration_id", "client_version", "source_status", "files"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise AdoptionError("runtime manifest envelope is invalid")
    if (
        manifest["schema_version"] != 1
        or manifest["integration_id"] != "leaf-first-adoption"
        or manifest["client_version"] != CLIENT_VERSION
        or manifest["source_status"] != "RELEASED"
    ):
        raise AdoptionError("runtime manifest identity is invalid or not released")
    expected = {
        "tools/__init__.py",
        "tools/adoptctl/__init__.py",
        "tools/adoptctl/__main__.py",
        "tools/adoptctl/cli.py",
        "tools/adoptctl/core.py",
        "tools/adoptctl/validator.py",
        "tools/leasectl/__init__.py",
        "tools/leasectl/core.py",
        "tools/topctl/__init__.py",
        "tools/topctl/cli.py",
    }
    actual: set[str] = set()
    if not isinstance(manifest["files"], list) or not manifest["files"]:
        raise AdoptionError("runtime manifest files are invalid")
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"logical_path", "role", "bytes", "sha256"}:
            raise AdoptionError("runtime manifest file entry is invalid")
        logical = entry["logical_path"]
        if not isinstance(logical, str) or logical in actual or entry["role"] != "python_runtime":
            raise AdoptionError("runtime manifest logical path is invalid")
        if (
            not isinstance(entry["bytes"], int)
            or isinstance(entry["bytes"], bool)
            or entry["bytes"] < 1
            or not isinstance(entry["sha256"], str)
            or not SHA256_RE.fullmatch(entry["sha256"])
        ):
            raise AdoptionError("runtime manifest file digest is invalid")
        actual.add(logical)
        source = runtime_root() / Path(*PurePosixPath(logical).parts)
        source_payload = _require_regular_file(source, f"runtime source {logical}")
        if len(source_payload) != entry["bytes"] or sha256_bytes(source_payload) != entry["sha256"]:
            raise AdoptionError(f"runtime manifest source mismatch: {logical}")
    if actual != expected:
        raise AdoptionError("runtime manifest does not have the exact adoptctl file set")
    return {"sha256": sha256_bytes(payload), "client_version": manifest["client_version"]}


def _live_release(control_plane: Path, release: str, commit: str) -> dict[str, str]:
    if release != _control_release_version(control_plane):
        raise AdoptionError("first adoption requires the exact current control release")
    if not OID_RE.fullmatch(commit):
        raise AdoptionError("candidate control-plane commit is invalid")
    if _git(control_plane, "symbolic-ref", "--quiet", "--short", "HEAD") != "main":
        raise AdoptionError("control-plane checkout must be on exact branch main")
    if _worktree_count(control_plane) != 1:
        raise AdoptionError("control-plane checkout must have exactly one worktree")
    if _parse_status(control_plane):
        raise AdoptionError("control-plane checkout must be clean")
    tag_ref = f"refs/tags/v{release}"
    tag_object = _git(control_plane, "rev-parse", tag_ref)
    if _git(control_plane, "cat-file", "-t", tag_ref) != "tag":
        raise AdoptionError("control release must be an annotated tag")
    peeled = _git(control_plane, "rev-parse", f"{tag_ref}^{{}}")
    head = _git(control_plane, "rev-parse", "HEAD")
    if peeled != commit or head != commit:
        raise AdoptionError("candidate release must exactly match the checked-out control release")
    tree = _git(control_plane, "rev-parse", "HEAD^{tree}")
    output = _git(control_plane, "ls-remote", "origin", tag_ref, f"{tag_ref}^{{}}", timeout_seconds=DEFAULT_NETWORK_TIMEOUT_SECONDS)
    live: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2:
            live[fields[1]] = fields[0]
    if live.get(tag_ref) != tag_object or live.get(f"{tag_ref}^{{}}") != peeled:
        raise AdoptionError("live remote annotated release identity mismatch")
    return {"release": release, "tag_object": tag_object, "commit": commit, "tree": tree}


def _render_from_payload(control_plane: Path, repo_payload: bytes, overlay_payload: bytes) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix="adoptctl-render-") as temporary:
        root = Path(temporary) / "leaf"
        overlay = root / ".toplayer" / "local" / "AGENTS.project.md"
        overlay.parent.mkdir(parents=True)
        (root / ".toplayer" / "repo.yaml").write_bytes(repo_payload)
        overlay.write_bytes(overlay_payload)
        composition = compose_render(root, control_plane)
        lock = (
            json.dumps(build_render_lock(composition), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        return lock, composition.rendered_bytes


def _payload_entries(package_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for logical_path in TARGET_PATHS:
        path = package_dir / "payload" / Path(*PurePosixPath(logical_path).parts)
        _assert_no_redirected_ancestors(package_dir, path)
        payload = _require_regular_file(path, f"package payload {logical_path}")
        entries.append({"path": logical_path, "bytes": len(payload), "sha256": sha256_bytes(payload)})
    return entries


def _validate_package_closure(package_dir: Path) -> None:
    expected_files = {
        PACKAGE_FILE,
        "payload/.toplayer/local/AGENTS.project.md",
        "payload/.toplayer/repo.yaml",
        "payload/.toplayer/render.lock.json",
        "payload/AGENTS.md",
    }
    expected_directories = {"", "payload", "payload/.toplayer", "payload/.toplayer/local"}
    found_files: set[str] = set()
    found_directories: set[str] = {""}
    pending = [(package_dir, "")]
    while pending:
        directory, prefix = pending.pop()
        if _is_redirect(directory) or not directory.is_dir():
            raise AdoptionError("package closure contains a redirected directory")
        for child in directory.iterdir():
            relative = f"{prefix}/{child.name}" if prefix else child.name
            if _is_redirect(child):
                raise AdoptionError("package closure contains a redirected path")
            if child.is_dir():
                found_directories.add(relative)
                pending.append((child, relative))
            elif child.is_file():
                found_files.add(relative)
            else:
                raise AdoptionError("package closure contains a non-regular entry")
    if found_files != expected_files or found_directories != expected_directories:
        raise AdoptionError("package closure contains an unexpected path")


def _freeze_package(
    control_plane: Path, package_dir: Path, package_sha256: str
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, bytes]]:
    """Read the strict package closure once under pinned ancestors."""

    package_dir = package_dir.absolute()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not _within_lexical(package_dir, temp_root):
        raise AdoptionError("package directory must be below the system temporary root")
    sentinel = package_dir / ".adoptctl-package-sentinel"
    with _pinned_ancestors(temp_root, sentinel):
        _validate_package_closure(package_dir)
        raw = _read_regular_bound(package_dir / PACKAGE_FILE, "package manifest")
        if sha256_bytes(raw) != package_sha256:
            raise AdoptionError("package SHA-256 mismatch")
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdoptionError("package manifest is invalid JSON") from error
        _assert_clean_tagged_control(control_plane)
        schema = json.loads(
            _require_regular_file(
                control_plane / "schemas" / "leaf_first_adoption_package.schema.json",
                "control package schema",
            ).decode("utf-8")
        )
        try:
            jsonschema.Draft202012Validator(schema).validate(manifest)
        except (jsonschema.ValidationError, jsonschema.SchemaError) as error:
            message = error.message if isinstance(error, jsonschema.ValidationError) else str(error)
            raise AdoptionError(f"package manifest schema validation failed: {message}") from error
        payloads = {
            logical_path: _read_regular_bound(
                package_dir / "payload" / Path(*PurePosixPath(logical_path).parts),
                f"package payload {logical_path}",
            )
            for logical_path in TARGET_PATHS
        }
        entries = [
            {"path": path, "bytes": len(payloads[path]), "sha256": sha256_bytes(payloads[path])}
            for path in TARGET_PATHS
        ]
        if manifest.get("outputs") != entries:
            raise AdoptionError("package payload hash binding mismatch")
        _assert_overlay_preimage_binding(manifest, payloads)
        _validate_package_closure(package_dir)
    return manifest, entries, payloads


def _validate_apply_gate(
    manifest: dict[str, Any],
    *,
    control_plane: Path,
    leaf_root: Path,
    runtime_manifest: Path,
    adopt_dirty: bool,
    network_timeout_seconds: int,
    require_target_preimages: bool,
) -> LeafGate:
    """Validate the narrow first-adoption gate without reading non-target bytes."""

    timeout = _network_timeout(network_timeout_seconds)
    release = manifest["control_release"]
    if not isinstance(release, dict) or set(release) != {"release", "tag_object", "commit", "tree"}:
        raise AdoptionError("package release identity is invalid")
    observed_release = _live_release(control_plane, release["release"], release["commit"])
    if observed_release != release:
        raise AdoptionError("control release identity changed")
    runtime = _validate_runtime_manifest(runtime_manifest, control_plane)
    if runtime != manifest["runtime"]:
        raise AdoptionError("runtime manifest identity changed")
    leaf = manifest["leaf"]
    if not isinstance(leaf, dict) or set(leaf) != {
        "repo_id",
        "remote_sha256",
        "identity",
        "target_preimages",
    }:
        raise AdoptionError("package leaf binding is invalid")
    registry_remote = _registry_remote(control_plane, leaf["repo_id"])
    if (
        _remote(leaf_root) != registry_remote
        or sha256_bytes(registry_remote.encode("utf-8")) != leaf["remote_sha256"]
    ):
        raise AdoptionError("leaf remote changed")
    current = _static_leaf_identity(leaf_root, timeout)
    expected = leaf["identity"]
    required = {"branch", "worktree_count", "head", "remote_main", "tree", "origin_sha256"}
    if not isinstance(expected, dict) or set(expected) != required:
        raise AdoptionError("package Git binding is invalid")
    if current != expected:
        raise AdoptionError("leaf branch, HEAD, live origin/main, worktree, or tree identity changed")
    staged_index = _staged_index_identity(leaf_root)
    if not staged_index["clean"]:
        raise AdoptionError("leaf staged index must be semantically clean before apply")
    _assert_no_partial_bootstrap_contamination(leaf_root)
    preimages = _preimages(leaf_root)
    if require_target_preimages and preimages != leaf["target_preimages"]:
        raise AdoptionError("target preimage changed or target path is contaminated")
    return LeafGate(
        identity=current,
        staged_index=staged_index,
        target_preimages=preimages,
    )


def plan(
    *,
    control_plane: Path,
    leaf_root: Path,
    repo_yaml: Path,
    package_dir: Path,
    runtime_manifest: Path,
    adopt_dirty: bool,
    network_timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    control_plane = control_plane.resolve()
    leaf_root = leaf_root.resolve()
    timeout = _network_timeout(network_timeout_seconds)
    _assert_runtime_isolated(control_plane, leaf_root, runtime_manifest)
    _git_root(control_plane)
    _git_root(leaf_root)
    package_dir = _validate_temp_package_dir(package_dir, control_plane, leaf_root)
    candidate, candidate_bytes = _validate_candidate(repo_yaml, control_plane)
    release = _live_release(control_plane, candidate["control_plane"]["release"], candidate["control_plane"]["commit_sha"])
    runtime = _validate_runtime_manifest(runtime_manifest, control_plane)
    leaf_remote = _registry_remote(control_plane, candidate["repo_id"])
    if _remote(leaf_root) != leaf_remote:
        raise AdoptionError("leaf origin does not match the candidate registry remote")
    identity = _static_leaf_identity(leaf_root, timeout)
    _assert_no_partial_bootstrap_contamination(leaf_root)
    preimages = _preimages(leaf_root)
    if any(entry["path"] != "AGENTS.md" and entry["state"] != "ABSENT" for entry in preimages):
        raise AdoptionError("first adoption rejects pre-existing bootstrap target contamination")
    overlay_bytes = _read_regular_bound(leaf_root / "AGENTS.md", "current leaf AGENTS.md")
    agents_preimage = preimages[3]
    if agents_preimage.get("bytes") != len(overlay_bytes) or agents_preimage.get("sha256") != sha256_bytes(overlay_bytes):
        raise AdoptionError("AGENTS preimage changed during package planning")
    lock_bytes, agents_bytes = _render_from_payload(control_plane, candidate_bytes, overlay_bytes)
    outputs = {
        ".toplayer/local/AGENTS.project.md": overlay_bytes,
        ".toplayer/repo.yaml": candidate_bytes,
        ".toplayer/render.lock.json": lock_bytes,
        "AGENTS.md": agents_bytes,
    }
    payload_root = package_dir / "payload"
    for logical_path, payload in outputs.items():
        target = payload_root / Path(*PurePosixPath(logical_path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    output_entries = _payload_entries(package_dir)
    manifest = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "kind": PACKAGE_KIND,
        "control_release": release,
        "runtime": runtime,
        "leaf": {
            "repo_id": candidate["repo_id"],
            "remote_sha256": sha256_bytes(leaf_remote.encode("utf-8")),
            "identity": identity,
            "target_preimages": preimages,
        },
        "outputs": output_entries,
    }
    raw = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    (package_dir / PACKAGE_FILE).write_bytes(raw)
    return {
        "result": "PLANNED",
        "package_sha256": sha256_bytes(raw),
        "outputs": [entry["path"] for entry in output_entries],
    }


def verify(
    *,
    control_plane: Path,
    leaf_root: Path,
    package_dir: Path,
    package_sha256: str,
    runtime_manifest: Path,
    adopt_dirty: bool,
    network_timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(package_sha256):
        raise AdoptionError("package SHA-256 is invalid")
    _assert_runtime_isolated(control_plane, leaf_root, runtime_manifest)
    manifest, entries, payloads = _freeze_package(control_plane.resolve(), package_dir, package_sha256)
    _validate_apply_gate(
        manifest,
        control_plane=control_plane.resolve(),
        leaf_root=leaf_root.resolve(),
        runtime_manifest=runtime_manifest.resolve(),
        adopt_dirty=adopt_dirty,
        network_timeout_seconds=network_timeout_seconds,
        require_target_preimages=True,
    )
    lock, rendered = _render_from_payload(
        control_plane.resolve(),
        payloads[".toplayer/repo.yaml"],
        payloads[".toplayer/local/AGENTS.project.md"],
    )
    expected = {entry["path"]: entry for entry in entries}
    for logical_path, actual in ((".toplayer/render.lock.json", lock), ("AGENTS.md", rendered)):
        entry = expected[logical_path]
        if len(actual) != entry["bytes"] or sha256_bytes(actual) != entry["sha256"]:
            raise AdoptionError("package topctl rendered bytes mismatch")
    return {
        "result": "VERIFIED",
        "package_sha256": package_sha256,
        "outputs": [entry["path"] for entry in entries],
    }


def _parse_timestamp(
    value: Any, label: str, *, allow_fractional: bool = True
) -> datetime:
    pattern = UTC_TIMESTAMP_RE if allow_fractional else WHOLE_SECOND_UTC_TIMESTAMP_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AdoptionError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(
            value[:-1],
            "%Y-%m-%dT%H:%M:%S.%f" if "." in value else "%Y-%m-%dT%H:%M:%S",
        )
    except ValueError as error:
        raise AdoptionError(f"{label} must be a UTC timestamp") from error
    return parsed.replace(tzinfo=timezone.utc)


def _utc_now(now_fn: Callable[[], datetime], label: str) -> datetime:
    value = now_fn()
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise AdoptionError(f"{label} must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _read_schema3_publish_evidence(
    *,
    evidence_path: Path,
    evidence_sha256: str,
    lease_id: str,
    owner: str,
    task: str,
    expires_at: str,
    reserve_seconds: int,
    manifest: dict[str, Any],
    gate: LeafGate,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(evidence_sha256):
        raise AdoptionError("schema3 publish evidence SHA-256 is invalid")
    if isinstance(reserve_seconds, bool) or not isinstance(reserve_seconds, int) or reserve_seconds < MIN_PUBLISH_RESERVE_SECONDS:
        raise AdoptionError(
            f"publish_reserve_seconds must be at least {MIN_PUBLISH_RESERVE_SECONDS}"
        )
    payload = _require_regular_file(evidence_path, "schema3 publish evidence")
    if sha256_bytes(payload) != evidence_sha256:
        raise AdoptionError("schema3 publish evidence SHA-256 mismatch")
    try:
        evidence = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdoptionError("schema3 publish evidence is invalid JSON") from error
    required = {
        "schema_version",
        "kind",
        "lease_id",
        "owner",
        "task",
        "state",
        "issued_at",
        "expires_at",
        "ttl_seconds",
        "shared_paths",
        "adapter_id",
        "adapter_version",
        "repo_id",
        "leaf_origin_sha256",
        "leaf_identity",
        "target_preimages",
        "registry_state_sha256",
    }
    if not isinstance(evidence, dict) or set(evidence) != required:
        raise AdoptionError("schema3 publish evidence envelope is invalid")
    required_nonempty = (
        "lease_id",
        "owner",
        "task",
        "adapter_id",
        "adapter_version",
        "repo_id",
    )
    if any(not isinstance(evidence.get(field), str) or not evidence[field] for field in required_nonempty):
        raise AdoptionError("schema3 publish evidence has an empty binding field")
    if (
        evidence["schema_version"] != 3
        or evidence["kind"] != "schema3_publish_lease_evidence"
        or evidence["state"] != "ACTIVE"
        or evidence["lease_id"] != lease_id
        or evidence["owner"] != owner
        or evidence["task"] != task
        or evidence["expires_at"] != expires_at
        or evidence["shared_paths"] != ["AGENTS.md"]
    ):
        raise AdoptionError("schema3 publish evidence does not match the explicit lease parameters")
    try:
        leaf = manifest["leaf"]
        expected_repo_id = leaf["repo_id"]
        expected_origin_sha256 = leaf["remote_sha256"]
        expected_identity = leaf["identity"]
        expected_preimages = leaf["target_preimages"]
    except (KeyError, TypeError) as error:
        raise AdoptionError("package leaf bindings are unavailable for schema3 evidence") from error
    if (
        evidence["adapter_id"] != SCHEMA3_ADAPTER_ID
        or evidence["adapter_version"] != SCHEMA3_ADAPTER_VERSION
        or evidence["repo_id"] != expected_repo_id
        or evidence["leaf_origin_sha256"] != expected_origin_sha256
        or evidence["leaf_identity"] != expected_identity
        or evidence["leaf_identity"] != gate.identity
        or evidence["target_preimages"] != expected_preimages
        or evidence["target_preimages"] != gate.target_preimages
        or not isinstance(evidence["registry_state_sha256"], str)
        or not SHA256_RE.fullmatch(evidence["registry_state_sha256"])
    ):
        raise AdoptionError("schema3 publish evidence does not bind this exact leaf gate")
    issued = _parse_timestamp(evidence["issued_at"], "schema3 publish evidence issued_at")
    expiry = _parse_timestamp(evidence["expires_at"], "schema3 publish evidence expires_at")
    ttl = evidence["ttl_seconds"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= MAX_SCHEMA3_PUBLISH_TTL_SECONDS:
        raise AdoptionError("schema3 publish evidence ttl_seconds must be an integer from 1 to 7200")
    if expiry != issued + timedelta(seconds=ttl):
        raise AdoptionError("schema3 publish evidence timestamps do not bind its TTL")
    now = _utc_now(now_fn, "schema3 publish evidence clock")
    if issued > now:
        raise AdoptionError("schema3 publish evidence issued_at must not be in the future")
    if expiry <= now + timedelta(seconds=reserve_seconds + MIN_FIRST_WRITE_BUDGET_SECONDS):
        raise AbortedPrewriteError("schema3 publish lease lacks the required first-write safety reserve")
    return {
        "sha256": evidence_sha256,
        "lease_id": lease_id,
        "owner": owner,
        "task": task,
        "state": "ACTIVE",
        "issued_at": evidence["issued_at"],
        "expires_at": expires_at,
        "ttl_seconds": ttl,
        "shared_paths": ["AGENTS.md"],
        "reserve_seconds": reserve_seconds,
        "adapter_id": evidence["adapter_id"],
        "adapter_version": evidence["adapter_version"],
        "repo_id": evidence["repo_id"],
        "leaf_origin_sha256": evidence["leaf_origin_sha256"],
        "leaf_identity": evidence["leaf_identity"],
        "target_preimages": evidence["target_preimages"],
        "registry_state_sha256": evidence["registry_state_sha256"],
    }


def _assert_schema3_deadline(
    schema3: dict[str, Any],
    *,
    phase: str,
    first_write: bool = False,
    finalization: bool = False,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    """Recheck immutable lease evidence at every brokered mutation boundary.

    The evidence is intentionally not renewed here.  Before a first write and
    before the durable COMMITTED receipt, retain a small execution cushion in
    addition to the caller's downstream reserve.  Once any target has moved,
    ordinary exhaustion raises a normal failure so the live PATH_LOCK rollback
    path can restore package-owned bytes.
    """

    try:
        expiry = _parse_timestamp(schema3["expires_at"], "schema3 publish evidence expires_at")
        reserve = schema3["reserve_seconds"]
    except (KeyError, TypeError) as error:
        raise AdoptionError("schema3 publish evidence deadline binding is invalid") from error
    if isinstance(reserve, bool) or not isinstance(reserve, int) or reserve < MIN_PUBLISH_RESERVE_SECONDS:
        raise AdoptionError("schema3 publish evidence deadline reserve is invalid")
    now = _utc_now(now_fn, "schema3 deadline clock")
    cushion = MIN_FIRST_WRITE_BUDGET_SECONDS if first_write or finalization else 0
    if expiry <= now + timedelta(seconds=reserve + cushion):
        if first_write:
            raise AbortedPrewriteError(
                f"schema3 publish lease lacks the required first-write safety reserve before {phase}"
            )
        raise AdoptionError(
            f"schema3 publish lease lacks the required downstream reserve before {phase}"
        )


def _assert_schema3_first_write_budget(
    schema3: dict[str, Any],
    *,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    """Compatibility shim for explicit first-write contract tests."""

    _assert_schema3_deadline(
        schema3,
        phase="first leaf mutation",
        first_write=True,
        now_fn=now_fn,
    )


class _Journal:
    """Fsynced, hash-chained external evidence with no host-path fields."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / JOURNAL_FILE
        self.receipt_path = directory / RECEIPT_FILE
        self._previous = "0" * 64
        self._sequence = 0
        # The strict PATH_LOCK watchdog records its own runtime state-file
        # events from a background thread.  Sequence/hash-chain construction
        # must be serialized with main-thread broker entries.
        self._append_lock = threading.RLock()
        self._sealed = False
        self._postcommit_invalidation_written = False
        # This counter is about the deliberately non-general broker API, not
        # an impossible whole-process/OS mutation claim.
        self.broker_non_target_successful_mutations = 0
        if self.path.exists() or self.receipt_path.exists():
            raise AdoptionError("journal directory must be new and empty")

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._append_lock:
            return self._append_locked(event, fields)

    def _append_locked(
        self,
        event: str,
        fields: dict[str, Any],
        *,
        allow_postcommit_partial: bool = False,
    ) -> dict[str, Any]:
        if self._sealed:
            if not (allow_postcommit_partial and event == "PARTIAL_APPLY"):
                raise AdoptionError("apply journal is sealed after COMMITTED")
        elif allow_postcommit_partial:
            raise AdoptionError("post-COMMITTED journal invalidation requires a sealed receipt")
        if not isinstance(event, str) or not event:
            raise AdoptionError("journal event must be non-empty text")
        record = {
            "sequence": self._sequence,
            "event": event,
            "previous_entry_sha256": self._previous,
            **fields,
        }
        digest = sha256_bytes(canonical_json_bytes(record))
        entry = {**record, "entry_sha256": digest}
        raw = canonical_json_bytes(entry) + b"\n"
        mode = "xb" if self._sequence == 0 else "ab"
        try:
            with self.path.open(mode) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise AdoptionError(f"journal cannot be fsync-written: {error}") from error
        self._previous = digest
        self._sequence += 1
        return entry

    def hash(self) -> str:
        with self._append_lock:
            return sha256_bytes(_require_regular_file(self.path, "apply journal"))

    def write_receipt(self, receipt: dict[str, Any]) -> None:
        raw = canonical_json_bytes(receipt) + b"\n"
        with self._append_lock:
            try:
                with self.receipt_path.open("xb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise AdoptionError(f"apply receipt cannot be fsync-written: {error}") from error

    @property
    def sealed(self) -> bool:
        with self._append_lock:
            return self._sealed

    def finalize_committed(
        self,
        *,
        committed_fields: dict[str, Any],
        receipt_fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Atomically append COMMITTED, bind its exact journal, then seal."""

        with self._append_lock:
            if self._sealed:
                raise AdoptionError("apply journal is already sealed")
            committed = self.append("COMMITTED", **committed_fields)
            receipt = {
                **receipt_fields,
                "journal_sha256": self.hash(),
                "committed_entry_sha256": committed["entry_sha256"],
            }
            # Do not mark the journal sealed until the receipt is fsync-durable.
            # A receipt failure must leave the normal CAS rollback terminal path
            # able to append its outcome evidence.
            self.write_receipt(receipt)
            self._sealed = True
            return receipt

    def append_postcommit_partial_invalidation(self, error: Exception) -> dict[str, Any]:
        """Invalidate a durable success receipt after later finalization fails.

        This deliberately narrow escape hatch is only for the main thread's
        post-COMMITTED failure classifier.  Ordinary broker/audit append paths
        remain sealed, so a watchdog cannot append after COMMITTED.
        """

        with self._append_lock:
            if threading.current_thread() is not threading.main_thread():
                raise AdoptionError("post-COMMITTED journal invalidation is main-thread-only")
            if self._postcommit_invalidation_written:
                raise AdoptionError("post-COMMITTED journal invalidation is already recorded")
            if not self._sealed:
                raise AdoptionError("post-COMMITTED journal invalidation requires a sealed receipt")
            entry = self._append_locked(
                "PARTIAL_APPLY",
                {"error": str(error)},
                allow_postcommit_partial=True,
            )
            self._postcommit_invalidation_written = True
            return entry


@dataclass(frozen=True)
class _Permit:
    event: str
    paths: tuple[Path, ...]


_AUDIT_LOCK = threading.RLock()
_ACTIVE_BROKER: _MutationBroker | None = None
_AUDIT_HOOK_INSTALLED = False


def _audit_path(value: Any) -> Path | None:
    if isinstance(value, int) or value is None:
        return None
    try:
        return Path(os.fsdecode(value)).absolute()
    except (TypeError, ValueError):
        return None


def _subprocess_argv(arguments: Any) -> list[str] | None:
    if isinstance(arguments, (list, tuple)):
        return [os.fsdecode(value) for value in arguments]
    if not isinstance(arguments, str):
        return None
    if os.name == "nt":
        count = ctypes.c_int()
        parser = ctypes.windll.shell32.CommandLineToArgvW
        parser.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        parser.restype = ctypes.POINTER(ctypes.c_wchar_p)
        pointer = parser(arguments, ctypes.byref(count))
        if not pointer:
            return None
        try:
            return [pointer[index] for index in range(count.value)]
        finally:
            release = ctypes.windll.kernel32.LocalFree
            release.argtypes = [ctypes.c_void_p]
            release.restype = ctypes.c_void_p
            release(ctypes.cast(pointer, ctypes.c_void_p))
    try:
        return shlex.split(arguments)
    except ValueError:
        return None


def _allowed_readonly_git_command(command: tuple[str, ...]) -> bool:
    """Accept only the exact non-mutating Git queries used by this writer."""

    allowed_exact = {
        ("rev-parse", "--git-common-dir"),
        ("rev-parse", "--git-dir"),
        ("rev-parse", "--show-toplevel", "--git-common-dir"),
        ("rev-parse", "--show-toplevel"),
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        ("worktree", "list", "--porcelain"),
        ("remote", "get-url", "origin"),
        ("remote", "get-url", "--push", "origin"),
        ("rev-parse", "HEAD"),
        ("rev-parse", "HEAD^{tree}"),
        ("diff", "--cached", "--raw", "-z", "--full-index"),
    }
    if command in allowed_exact:
        return True
    if len(command) == 3 and command[:2] == ("cat-file", "-t"):
        return command[2].startswith("refs/tags/v")
    if len(command) == 2 and command[0] == "rev-parse":
        return command[1].startswith("refs/tags/v")
    return (
        len(command) in {3, 4}
        and command[:2] == ("ls-remote", "origin")
        and all(item.startswith("refs/") for item in command[2:])
    )


def _readonly_git_details(
    executable: Any,
    arguments: Any,
    cwd: Any,
    environment: Any,
    *,
    allowed_worktree: Path,
) -> tuple[list[str], str] | None:
    """Validate executable, argv, cwd, and canonical environment as one tuple."""

    argv = _subprocess_argv(arguments)
    if argv is None or len(argv) < 2 or not isinstance(cwd, (str, bytes, os.PathLike)):
        return None
    # Heartbeat Git observations use leasectl's distinct sanitized tuple.
    # Match its complete argv, executable, cwd, environment and exact leaf root.
    for command in lock_core._READ_ONLY_GIT_COMMANDS:
        if argv[-len(command):] != list(command):
            continue
        try:
            expected_argv, expected_environment, expected_cwd = lock_core._git_observation_spec(
                allowed_worktree, list(command)
            )
            invoked_executable = Path(os.fsdecode(executable)).absolute()
            invoked_cwd = Path(os.fsdecode(cwd)).absolute()
        except (LockError, OSError, TypeError, ValueError):
            return None
        if (argv == expected_argv
            and invoked_executable == Path(expected_argv[0])
            and invoked_cwd == Path(expected_cwd)
            and isinstance(environment, dict)
            and environment == expected_environment):
            return list(command), _git_environment_sha256(environment)
        break
    try:
        pinned = _pinned_git_executable()
        invoked = Path(os.fsdecode(argv[0])).absolute()
        selected = Path(os.fsdecode(executable)).absolute()
        invocation_cwd = Path(os.fsdecode(cwd)).absolute()
    except (TypeError, ValueError):
        return None
    if (
        invoked != pinned
        or selected != pinned
        or invocation_cwd != allowed_worktree.absolute()
        or not isinstance(environment, dict)
        or environment != _sanitized_git_environment()
    ):
        return None
    command = tuple(argv[1:])
    if not _allowed_readonly_git_command(command):
        return None
    return list(command), _git_environment_sha256(environment)


def _readonly_git_invocation(
    executable: Any,
    arguments: Any,
    cwd: Any,
    environment: Any,
    *,
    allowed_worktree: Path,
) -> bool:
    """Boolean public predicate retained for hostile-input contract tests."""

    return _readonly_git_details(
        executable,
        arguments,
        cwd,
        environment,
        allowed_worktree=allowed_worktree,
    ) is not None


def _install_audit_hook() -> None:
    global _AUDIT_HOOK_INSTALLED
    with _AUDIT_LOCK:
        if _AUDIT_HOOK_INSTALLED:
            return

        def hook(event: str, args: tuple[Any, ...]) -> None:
            with _AUDIT_LOCK:
                broker = _ACTIVE_BROKER
            if broker is not None:
                broker.audit(event, args)

        sys.addaudithook(hook)
        _AUDIT_HOOK_INSTALLED = True


class _MutationBroker:
    """Narrow released-writer broker with defense-in-depth audit records.

    Python audit hooks are deliberately not treated as an OS sandbox: they do
    not mediate raw descriptors, ``os.write``, ``dir_fd`` operations, ctypes,
    or already-open handles.  The operational assurance is the hash-bound
    released writer's deliberately non-general mutation API, sanitized Git
    subprocess tuple, anchored journal, and current post-state check.
    """

    def __init__(self, leaf_root: Path, coordinator: LockCoordinator, journal: _Journal) -> None:
        self.leaf_root = leaf_root.absolute()
        self.runtime_dir = coordinator.runtime_dir.absolute()
        self.journal = journal
        self._journal_paths = {journal.path.absolute(), journal.receipt_path.absolute()}
        self._target_logicals = {
            _target_path(self.leaf_root, logical_path).absolute(): logical_path
            for logical_path in TARGET_PATHS
        }
        self._permit_local = threading.local()
        self._entered = False
        self.successful_leaf_mutations = 0
        self.broker_non_target_successful_mutations = 0
        self.scaffold_created = False
        self._temporary_paths: set[Path] = set()
        self._temporary_identities: dict[Path, dict[str, Any]] = {}
        self._temporary_targets: dict[Path, Path] = {}
        self._replaced_temporaries: set[Path] = set()
        self._rollback_replacements: set[str] = set()
        self.replaced_targets: set[str] = set()

    def __enter__(self) -> _MutationBroker:
        global _ACTIVE_BROKER
        _install_audit_hook()
        with _AUDIT_LOCK:
            if _ACTIVE_BROKER is not None:
                raise AdoptionError("only one in-process leaf mutation broker may be active")
            _ACTIVE_BROKER = self
        self._entered = True
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        global _ACTIVE_BROKER
        with _AUDIT_LOCK:
            if _ACTIVE_BROKER is self:
                _ACTIVE_BROKER = None
        self._entered = False

    def _under_leaf(self, path: Path) -> bool:
        return _within_lexical(path, self.leaf_root)

    def _runtime_allowed(self, path: Path) -> bool:
        if not _within_lexical(path, self.runtime_dir):
            return False
        relative = path.absolute().relative_to(self.runtime_dir).as_posix()
        return relative in {"state.lock", "state.json"} or bool(
            _RUNTIME_STATE_TEMP_RE.fullmatch(relative)
        )

    def _journal_allowed(self, path: Path) -> bool:
        return path.absolute() in self._journal_paths

    def _logical(self, path: Path) -> str:
        if self._under_leaf(path):
            return path.absolute().relative_to(self.leaf_root).as_posix()
        if self._runtime_allowed(path):
            return ".git/toplayer-runtime/leases-v1/" + path.absolute().relative_to(self.runtime_dir).as_posix()
        return "external-journal"

    def _canonical_target(self, path: Path) -> tuple[Path, str]:
        target = path.absolute()
        logical_path = self._target_logicals.get(target)
        if logical_path is None:
            raise MutationAuditError("broker target is not one of the canonical four paths")
        expected = _target_path(self.leaf_root, logical_path).absolute()
        if target != expected:
            raise MutationAuditError("broker target does not have its canonical path identity")
        return target, logical_path

    def _tracked_temporary_target(
        self,
        temporary: Path,
        *,
        allow_consumed: bool = False,
    ) -> Path:
        temporary = temporary.absolute()
        target = self._temporary_targets.get(temporary)
        if target is None or temporary not in self._temporary_paths:
            raise MutationAuditError("broker temporary is not an exact tracked temporary")
        if temporary.parent != target.parent:
            raise MutationAuditError("broker temporary is not in its canonical target parent")
        expected = self._temporary_identities.get(temporary)
        if expected is None:
            raise MutationAuditError("broker temporary has no tracked identity")
        if not os.path.lexists(temporary):
            if allow_consumed and temporary in self._replaced_temporaries:
                return target
            raise PartialApplyError("tracked temporary vanished before its brokered action")
        if _path_identity(temporary, self._logical(temporary)) != expected:
            raise PartialApplyError("tracked temporary changed before its brokered action")
        return target

    def _discard_temporary(self, temporary: Path) -> None:
        temporary = temporary.absolute()
        self._temporary_paths.discard(temporary)
        self._temporary_identities.pop(temporary, None)
        self._temporary_targets.pop(temporary, None)

    @contextmanager
    def permit(self, event: str, *paths: Path) -> Iterator[None]:
        previous = getattr(self._permit_local, "permit", None)
        self._permit_local.permit = _Permit(event, tuple(path.absolute() for path in paths))
        try:
            yield
        finally:
            self._permit_local.permit = previous

    def _reject(self, event: str, paths: Iterable[Path]) -> None:
        rendered = [self._logical(path) for path in paths]
        self.journal.append("AUDIT_REJECTED", audit_event=event, paths=rendered)
        raise MutationAuditError(f"mutation audit rejected {event} outside the first-adoption closure")

    def _allow_or_reject(self, event: str, paths: tuple[Path, ...]) -> None:
        if all(self._journal_allowed(path) for path in paths):
            # Journal writes are separately fsync-bound.  Logging this allow
            # record would recursively append to that same journal.
            return
        if all(self._runtime_allowed(path) for path in paths):
            self.journal.append(
                "AUDIT_ALLOWED",
                audit_event=event,
                scope="path_lock_runtime",
                paths=[self._logical(path) for path in paths],
            )
            return
        if not all(self._under_leaf(path) for path in paths):
            self._reject(event, paths)
        permit = getattr(self._permit_local, "permit", None)
        if permit is None or permit.event != event or permit.paths != paths:
            self._reject(event, paths)
        self.journal.append(
            "AUDIT_ALLOWED",
            audit_event=event,
            scope="leaf_closed_writer",
            paths=[self._logical(path) for path in paths],
        )

    def audit(self, event: str, args: tuple[Any, ...]) -> None:
        if event == "subprocess.Popen":
            executable = args[0] if args else None
            arguments = args[1] if len(args) > 1 else None
            cwd = args[2] if len(args) > 2 else None
            environment = args[3] if len(args) > 3 else None
            details = _readonly_git_details(
                executable,
                arguments,
                cwd,
                environment,
                allowed_worktree=self.leaf_root,
            )
            if details is None:
                rendered = _subprocess_argv(arguments) or []
                command = rendered[1:4] if len(rendered) > 1 else rendered[:3]
                self.journal.append(
                    "AUDIT_REJECTED",
                    audit_event=event,
                    paths=["subprocess"],
                    command=command,
                    argument_type=type(arguments).__name__,
                )
                raise MutationAuditError("mutation audit rejected subprocess outside the read-only Git allowlist")
            logical_command, environment_sha256 = details
            self.journal.append(
                "AUDIT_ALLOWED",
                audit_event=event,
                scope=("lock_read_only_git" if environment_sha256 ==
                       _git_environment_sha256(lock_core._git_observation_environment())
                       else "read_only_git"),
                logical_command=logical_command,
                sanitized_env_sha256=environment_sha256,
            )
            return
        if event == "open":
            path = _audit_path(args[0] if args else None)
            flags = args[2] if len(args) > 2 else 0
            if path is None or not isinstance(flags, int):
                return
            write_bits = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            if flags & write_bits:
                self._allow_or_reject("open", (path,))
            return
        if event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime", "os.symlink", "os.link"}:
            path = _audit_path(args[0] if args else None)
            if path is not None:
                self._allow_or_reject(event, (path,))
            return
        if event in {"os.rename", "os.replace"}:
            source = _audit_path(args[0] if args else None)
            destination = _audit_path(args[1] if len(args) > 1 else None)
            if source is not None and destination is not None:
                self._allow_or_reject("os.rename", (source, destination))

    def _mutation(
        self,
        *,
        operation: str,
        audit_event: str,
        paths: tuple[Path, ...],
        preimage: dict[str, Any],
        action: Callable[[], Any],
        postimage: Callable[[], dict[str, Any]],
        on_action_succeeded: Callable[[], None] | None = None,
    ) -> Any:
        logical_paths = [self._logical(path) for path in paths]
        self.journal.append(
            "MUTATION_INTENT",
            operation=operation,
            audit_event=audit_event,
            paths=logical_paths,
            preimage=preimage,
        )
        try:
            with self.permit(audit_event, *paths):
                result = action()
            # The OS action has returned successfully.  Conservatively account
            # for that fact before a postimage read or result-journal fsync can
            # fail: otherwise a reached bootstrap/target could be misreported
            # as a zero-write preflight failure.
            if any(self._under_leaf(path) and not self._runtime_allowed(path) for path in paths):
                self.successful_leaf_mutations += 1
            if on_action_succeeded is not None:
                on_action_succeeded()
            post = postimage()
        except Exception as error:
            self.journal.append(
                "MUTATION_RESULT",
                operation=operation,
                audit_event=audit_event,
                paths=logical_paths,
                success=False,
                error=str(error),
            )
            raise
        self.journal.append(
            "MUTATION_RESULT",
            operation=operation,
            audit_event=audit_event,
            paths=logical_paths,
            success=True,
            postimage=post,
        )
        return result

    def mkdir(self, path: Path) -> None:
        path = path.absolute()
        if path not in {self.leaf_root / ".toplayer", self.leaf_root / ".toplayer" / "local"}:
            raise MutationAuditError("only canonical bootstrap directories may be created")
        before = {"state": "PRESENT_DIRECTORY" if path.exists() else "ABSENT"}
        if path.exists():
            if _is_redirect(path) or not path.is_dir():
                raise AdoptionError("bootstrap parent is redirected or not a directory")
            return
        self._mutation(
            operation="mkdir",
            audit_event="os.mkdir",
            paths=(path,),
            preimage=before,
            action=path.mkdir,
            postimage=lambda: {"state": "PRESENT_DIRECTORY" if path.is_dir() and not _is_redirect(path) else "INVALID"},
            on_action_succeeded=lambda: setattr(self, "scaffold_created", True),
        )

    def create_temp(self, target: Path, payload: bytes) -> Path:
        target, _ = self._canonical_target(target)
        temporary = target.parent / f".adoptctl-{uuid.uuid4().hex}.tmp"
        if temporary.parent != target.parent:
            raise MutationAuditError("temporary path is outside its canonical target directory")
        self._temporary_paths.add(temporary)
        self._temporary_targets[temporary] = target

        created_metadata: dict[str, os.stat_result | None] = {"value": None}

        def write() -> None:
            # On Windows, os.open otherwise inherits text mode and expands an
            # already-canonical CRLF payload into CRCRLF.  Package payloads
            # are byte commitments, so the same-dir temporary must be binary.
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                created_metadata["value"] = os.fstat(descriptor)
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        try:
            self._mutation(
                operation="temp_create",
                audit_event="open",
                paths=(temporary,),
                preimage={"state": "ABSENT"},
                action=write,
                postimage=lambda: _path_identity(temporary, self._logical(temporary)),
            )
        except Exception:
            metadata = created_metadata["value"]
            if metadata is not None and os.path.lexists(temporary):
                current = temporary.lstat()
                if (
                    _is_redirect(temporary)
                    or not stat.S_ISREG(current.st_mode)
                    or not os.path.samestat(metadata, current)
                ):
                    raise PartialApplyError("failed temporary changed before cleanup")
                self._temporary_identities[temporary] = _path_identity(
                    temporary, self._logical(temporary)
                )
                self.unlink(temporary, operation="temp_cleanup_failed_create")
            else:
                self._discard_temporary(temporary)
            raise
        self._temporary_identities[temporary] = _path_identity(temporary, self._logical(temporary))
        return temporary

    def replace(
        self,
        temporary: Path,
        target: Path,
        *,
        operation: str = "replace_target",
    ) -> None:
        temporary = temporary.absolute()
        target, logical_target = self._canonical_target(target)
        tracked_target = self._tracked_temporary_target(temporary)
        if tracked_target != target or temporary.parent != target.parent:
            raise MutationAuditError("broker replacement temporary and target do not share the tracked parent")
        if operation == "replace_target":
            if logical_target in self.replaced_targets:
                raise MutationAuditError("broker target may be forward-replaced only once")
        elif operation == "rollback_replace_target":
            if (
                logical_target not in self.replaced_targets
                or logical_target in self._rollback_replacements
            ):
                raise MutationAuditError("broker rollback replacement is not unique for a reached target")
        else:
            raise MutationAuditError("broker replacement operation is not permitted")
        if temporary in self._replaced_temporaries:
            raise MutationAuditError("broker temporary may be replaced only once")
        def mark_reached() -> None:
            self._replaced_temporaries.add(temporary)
            if operation == "replace_target":
                self.replaced_targets.add(logical_target)
            else:
                self._rollback_replacements.add(logical_target)

        self._mutation(
            operation=operation,
            audit_event="os.rename",
            paths=(temporary, target),
            preimage={"target": _path_identity(target, self._logical(target))},
            action=lambda: os.replace(temporary, target),
            postimage=lambda: {"target": _path_identity(target, self._logical(target))},
            on_action_succeeded=mark_reached,
        )

    def unlink(self, path: Path, *, operation: str) -> None:
        path = path.absolute()
        if operation in {"temp_unlink", "temp_cleanup_failed_create"}:
            self._tracked_temporary_target(
                path,
                allow_consumed=operation == "temp_unlink",
            )
            if not os.path.lexists(path):
                # os.replace has already consumed the exact same-directory
                # temp.  Keep the finalizer observable (and therefore
                # fault-testable) without manufacturing a second target
                # mutation or touching a subsequently absent path.
                self._discard_temporary(path)
                return
            self._mutation(
                operation=operation,
                audit_event="os.remove",
                paths=(path,),
                preimage=_path_identity(path, self._logical(path)),
                action=path.unlink,
                postimage=lambda: {"state": "ABSENT"},
            )
            self._discard_temporary(path)
            return
        if operation == "rollback_unlink_target":
            target, logical_target = self._canonical_target(path)
            if (
                logical_target not in self.replaced_targets
                or logical_target in self._rollback_replacements
            ):
                raise MutationAuditError("broker rollback unlink is not unique for a reached target")
            self._mutation(
                operation=operation,
                audit_event="os.remove",
                paths=(target,),
                preimage=_path_identity(target, self._logical(target)),
                action=target.unlink,
                postimage=lambda: {"state": "ABSENT"},
                on_action_succeeded=lambda: self._rollback_replacements.add(logical_target),
            )
            return
        raise MutationAuditError("broker unlink operation is not permitted")

    def assert_no_live_temporaries(self) -> None:
        remaining = [path for path in self._temporary_paths if path.exists()]
        if remaining:
            raise PartialApplyError("apply left a same-directory temporary file behind")


class _LockWatchdog:
    """Strict renewal watchdog: no recovery, no lock-gap repair."""

    def __init__(
        self,
        coordinator: LockCoordinator,
        lock: dict[str, Any],
        owner: str,
        ttl_seconds: int,
    ) -> None:
        self.coordinator = coordinator
        self._lock_record = lock
        self.owner = owner
        # Lease timestamps are whole seconds: reserve the lost fractional
        # second before waiting, so fresh Git checks fit short heartbeats.
        self.interval_seconds = max(0.05, ttl_seconds / 3 - 1.0)
        self._guard = threading.RLock()
        self._stop = threading.Event()
        self._failure: LockContinuityError | None = None
        self._next = time.monotonic() + self.interval_seconds
        self._thread = threading.Thread(target=self._run, name="adoptctl-strict-heartbeat", daemon=True)

    @property
    def lock(self) -> dict[str, Any]:
        with self._guard:
            return dict(self._lock_record)

    def start(self) -> None:
        self._thread.start()

    def _renew_locked(self) -> None:
        if self._failure is not None:
            raise self._failure
        try:
            renewed = self.coordinator.renew_active(
                lock_id=self._lock_record["lock_id"],
                owner=self.owner,
                nonce=self._lock_record["nonce"],
                new_nonce=self._lock_record["nonce"],
                ttl_seconds=self._lock_record["ttl_seconds"],
            )
        except LockError as error:
            self._failure = LockContinuityError(f"apply PATH_LOCK strict heartbeat failed: {error}")
            raise self._failure from error
        if renewed.get("status") != "RENEWED":
            self._failure = LockContinuityError("apply PATH_LOCK strict heartbeat did not renew")
            raise self._failure
        self._lock_record = renewed["lock"]
        self._next = time.monotonic() + self.interval_seconds

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                with self._guard:
                    if self._stop.is_set():
                        return
                    self._renew_locked()
            except LockContinuityError:
                return

    def check_live(self) -> None:
        with self._guard:
            if self._failure is not None:
                raise self._failure
            if time.monotonic() >= self._next:
                self._renew_locked()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_seconds + 0.5))

    def quiesce_for_finalization(self) -> None:
        """Strict-renew once, then join heartbeat before sealing COMMITTED."""

        with self._guard:
            if self._failure is not None:
                raise self._failure
            # Reset the live strict lease immediately before the intentionally
            # short sealed receipt critical section.  This emits any final
            # runtime audit record before COMMITTED rather than racing after it.
            self._renew_locked()
            self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_seconds + 0.5))
        if self._thread.is_alive():
            failure = LockContinuityError("apply PATH_LOCK watchdog did not quiesce for finalization")
            with self._guard:
                self._failure = failure
            raise failure
        with self._guard:
            if self._failure is not None:
                raise self._failure

    def release(self) -> dict[str, Any]:
        self.check_live()
        self.stop()
        lock = self.lock
        try:
            released = self.coordinator.release(
                lock_id=lock["lock_id"], owner=self.owner, nonce=lock["nonce"]
            )
        except LockError as error:
            raise PartialApplyError(f"apply PATH_LOCK release failed: {error}") from error
        if released.get("observed_state") != "ACTIVE":
            raise LockContinuityError("apply PATH_LOCK was not active when released")
        return released


def _path_identity(path: Path, logical_path: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"path": logical_path, "state": "ABSENT"}
    if _is_redirect(path) or not stat.S_ISREG(metadata.st_mode):
        return {"path": logical_path, "state": "NON_REGULAR_OR_REDIRECTED"}
    payload = _read_regular_bound(path, f"journal path {logical_path}")
    return {
        "path": logical_path,
        "state": "PRESENT",
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _payload_identity(logical_path: str, payload: bytes | None) -> dict[str, Any]:
    if payload is None:
        return {"path": logical_path, "state": "ABSENT"}
    return {
        "path": logical_path,
        "state": "PRESENT",
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _assert_target_matches(
    root: Path,
    logical_path: str,
    expected: dict[str, Any],
    *,
    phase: str,
) -> None:
    actual = _target_identity(root, logical_path)
    if actual != expected:
        raise AdoptionError(f"target preimage changed immediately before {phase}: {logical_path}")


def _ensure_bootstrap_directories(
    root: Path,
    broker: _MutationBroker,
    watchdog: _LockWatchdog,
    schema3: dict[str, Any],
    *,
    schema3_now_fn: Callable[[], datetime],
) -> None:
    for logical in (".toplayer", ".toplayer/local"):
        directory = root / Path(*PurePosixPath(logical).parts)
        _assert_no_redirected_ancestors(root, directory / ".adoptctl-directory-sentinel")
        if directory.exists():
            if _is_redirect(directory) or not directory.is_dir():
                raise AdoptionError("bootstrap parent is redirected or not a directory")
            continue
        _assert_schema3_deadline(
            schema3,
            phase=f"bootstrap mkdir {logical}",
            first_write=broker.successful_leaf_mutations == 0,
            now_fn=schema3_now_fn,
        )
        watchdog.check_live()
        broker.mkdir(directory)


def _write_target(
    root: Path,
    logical_path: str,
    payload: bytes,
    *,
    expected_preimage: dict[str, Any],
    broker: _MutationBroker,
    watchdog: _LockWatchdog,
    schema3: dict[str, Any] | None,
    schema3_now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    replace_operation: str = "replace_target",
) -> None:
    target = _target_path(root, logical_path)
    _assert_no_redirected_ancestors(root, target)
    watchdog.check_live()
    with _pinned_ancestors(root, target):
        temporary: Path | None = None
        try:
            if schema3 is not None:
                _assert_schema3_deadline(
                    schema3,
                    phase=f"same-directory temporary for {logical_path}",
                    first_write=broker.successful_leaf_mutations == 0,
                    now_fn=schema3_now_fn,
                )
            watchdog.check_live()
            temporary = broker.create_temp(target, payload)
            watchdog.check_live()
            with _pinned_ancestors(root, target):
                if schema3 is not None:
                    _assert_schema3_deadline(
                        schema3,
                        phase=f"atomic replace for {logical_path}",
                        now_fn=schema3_now_fn,
                    )
                watchdog.check_live()
                if _is_redirect(target) or (target.exists() and not target.is_file()):
                    raise AdoptionError("target became redirected or non-regular during apply")
                # Ordinary os.replace is not a cross-process CAS.  This is the
                # last possible protocol-respecting preimage check while path
                # ancestors are pinned; a non-protocol foreign writer can still
                # race it, so final postchecks remain mandatory.
                _assert_target_matches(
                    root,
                    logical_path,
                    expected_preimage,
                    phase="atomic replace",
                )
                broker.replace(temporary, target, operation=replace_operation)
        finally:
            # Run the tracked-temp finalizer even after a successful replace.
            # It becomes a safe no-op when os.replace consumed the source, but
            # it preserves an auditable heartbeat/fault boundary and cleans a
            # temp left behind by a failed replacement.  This is recovery work
            # under the still-live PATH_LOCK, so an already-exhausted schema-3
            # downstream reserve must not strand the tracked temporary or
            # prevent a subsequently provable CAS rollback.
            if temporary is not None:
                watchdog.check_live()
                broker.unlink(temporary, operation="temp_unlink")


def _entry_payload(entry: dict[str, Any], backups: dict[str, bytes | None]) -> bytes | None:
    try:
        return backups[entry["path"]]
    except KeyError as error:
        raise PartialApplyError("rollback backup is incomplete") from error


def _restore(
    root: Path,
    backups: dict[str, bytes | None],
    outputs: dict[str, bytes],
    replaced_targets: set[str],
    target_preimages: list[dict[str, Any]],
    *,
    broker: _MutationBroker,
    watchdog: _LockWatchdog,
) -> None:
    """Protocol-scoped CAS rollback for writers honoring schema3 + PATH_LOCK."""

    expected_preimages = {entry["path"]: entry for entry in target_preimages}
    for logical_path in ROLLBACK_PATHS:
        if logical_path not in replaced_targets:
            continue
        watchdog.check_live()
        target = _target_path(root, logical_path)
        output = _payload_identity(logical_path, outputs[logical_path])
        original = _entry_payload({"path": logical_path}, backups)
        preimage = _payload_identity(logical_path, original)
        if preimage != expected_preimages.get(logical_path):
            raise PartialApplyError(f"rollback backup does not match gate preimage for {logical_path}")
        with _pinned_ancestors(root, target):
            current = _target_identity(root, logical_path)
            if current == preimage:
                # The write call may have failed after another local rollback
                # attempt.  It is already restored, so do not manufacture a
                # second target mutation.
                continue
            if current != output:
                raise PartialApplyError(
                    f"rollback CAS refused foreign current bytes for {logical_path}"
                )
            if original is None:
                # Re-read at the immediate unlink boundary.  This remains a
                # protocol-level CAS check, not an OS primitive that can stop
                # a non-cooperating foreign writer between check and unlink.
                watchdog.check_live()
                _assert_target_matches(
                    root,
                    logical_path,
                    output,
                    phase="rollback unlink",
                )
                broker.unlink(target, operation="rollback_unlink_target")
            else:
                _write_target(
                    root,
                    logical_path,
                    original,
                    expected_preimage=output,
                    broker=broker,
                    watchdog=watchdog,
                    schema3=None,
                    replace_operation="rollback_replace_target",
                )


def _postcheck(
    gate: LeafGate,
    entries: list[dict[str, Any]],
    *,
    leaf_root: Path,
    network_timeout_seconds: int,
) -> None:
    after = _static_leaf_identity(leaf_root, network_timeout_seconds)
    if after != gate.identity:
        raise AdoptionError("post-apply branch, HEAD, live origin/main, worktree, tree, or remote changed")
    index = _staged_index_identity(leaf_root)
    if index != gate.staged_index or not index["clean"]:
        raise AdoptionError("post-apply staged index changed")
    expected = {entry["path"]: entry for entry in entries}
    for logical_path in TARGET_PATHS:
        actual = _target_identity(leaf_root, logical_path)
        entry = expected[logical_path]
        if actual != {
            "path": logical_path,
            "state": "PRESENT",
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
        }:
            raise AdoptionError(
                "post-apply target bytes mismatch for "
                f"{logical_path}: expected={entry['sha256']} actual={actual.get('sha256')}"
            )


def _journal_prepared(
    journal: _Journal,
    *,
    manifest: dict[str, Any],
    package_sha256: str,
    gate: LeafGate,
    schema3: dict[str, Any],
    lock: dict[str, Any],
    entries: list[dict[str, Any]],
    network_timeout_seconds: int,
) -> dict[str, Any]:
    return journal.append(
        "PREPARED",
        package_sha256=package_sha256,
        control_release=manifest["control_release"],
        runtime=manifest["runtime"],
        manifest_leaf_identity=manifest["leaf"]["identity"],
        manifest_target_preimages=manifest["leaf"]["target_preimages"],
        leaf_identity=gate.identity,
        staged_index=gate.staged_index,
        target_preimages=gate.target_preimages,
        outputs=entries,
        schema3_publish=schema3,
        path_lock={
            "lock_id": lock["lock_id"],
            "owner": lock["owner"],
            "task": lock["task"],
            "acquired_at": lock["acquired_at"],
            "expires_at": lock["expires_at"],
            "ttl_seconds": lock["ttl_seconds"],
            "nonce_sha256": sha256_bytes(lock["nonce"].encode("utf-8")),
            "paths": lock["paths"],
        },
        git_sanitized_env_sha256=_git_environment_sha256(_sanitized_git_environment()),
        lock_git_sanitized_env_sha256=_git_environment_sha256(lock_core._git_observation_environment()),
        network_timeout_seconds=network_timeout_seconds,
    )


def _write_committed_receipt(
    journal: _Journal,
    *,
    package_sha256: str,
    entries: list[dict[str, Any]],
    gate: LeafGate,
    broker: _MutationBroker,
    prepared_entry_sha256: str,
) -> dict[str, Any]:
    return journal.finalize_committed(
        committed_fields={
            "package_sha256": package_sha256,
            "outputs": entries,
            "four_postimages": entries,
            "staged_index": gate.staged_index,
            "prepared_entry_sha256": prepared_entry_sha256,
            "broker_non_target_successful_mutations": broker.broker_non_target_successful_mutations,
        },
        receipt_fields={
            "schema_version": 1,
            "kind": "leaf_first_adoption_apply_receipt",
            "result": "APPLIED",
            "package_sha256": package_sha256,
            "journal_file": JOURNAL_FILE,
            "prepared_entry_sha256": prepared_entry_sha256,
            "outputs": entries,
            "four_postimages": entries,
            "staged_index": gate.staged_index,
            "broker_non_target_successful_mutations": broker.broker_non_target_successful_mutations,
        },
    )


def _record_terminal(journal: _Journal | None, result: str, error: Exception) -> None:
    if journal is None:
        return
    if journal.sealed:
        if result != "PARTIAL_APPLY":
            raise AdoptionError("sealed COMMITTED journal may only receive PARTIAL_APPLY invalidation")
        journal.append_postcommit_partial_invalidation(error)
        return
    journal.append(result, error=str(error))


def apply(
    *,
    control_plane: Path,
    leaf_root: Path,
    package_dir: Path,
    package_sha256: str,
    runtime_manifest: Path,
    adopt_dirty: bool,
    exclusive_writer_ack: str,
    task: str,
    owner: str,
    journal_dir: Path,
    schema3_publish_evidence: Path,
    schema3_publish_evidence_sha256: str,
    schema3_publish_lease_id: str,
    schema3_publish_owner: str,
    schema3_publish_task: str,
    schema3_publish_expires_at: str,
    publish_reserve_seconds: int = DEFAULT_PUBLISH_RESERVE_SECONDS,
    path_lock_ttl_seconds: int = DEFAULT_PATH_LOCK_TTL_SECONDS,
    network_timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
    schema3_now_fn: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Apply a v3 package through a narrow, auditable, strict-lock writer."""

    if not adopt_dirty:
        # Do not try to discover whether the leaf is dirty: that would require
        # a global, racing non-closed worktree scan.  The current writer requires this
        # explicit caller acknowledgement for every mutating apply instead.
        raise AdoptionError("apply requires explicit --adopt-dirty")
    if exclusive_writer_ack != ACKNOWLEDGEMENT:
        raise AdoptionError("apply requires --exclusive-writer-ack HELD_UNDER_LEAF_POLICY")
    if not SHA256_RE.fullmatch(package_sha256):
        raise AdoptionError("package SHA-256 is invalid")
    if isinstance(path_lock_ttl_seconds, bool) or not isinstance(path_lock_ttl_seconds, int) or path_lock_ttl_seconds < 1:
        raise AdoptionError("path_lock_ttl_seconds must be a positive integer")
    if schema3_now_fn is not None and not callable(schema3_now_fn):
        raise AdoptionError("schema3_now_fn must be callable when provided")
    deadline_now_fn = schema3_now_fn or (lambda: datetime.now(timezone.utc))
    timeout = _network_timeout(network_timeout_seconds)
    control_plane = control_plane.resolve()
    leaf_root = leaf_root.resolve()
    _assert_runtime_isolated(control_plane, leaf_root, runtime_manifest)
    journal_dir = _validate_journal_dir(journal_dir, control_plane, leaf_root)

    # Package freeze and deterministic render validation happen before the
    # caller's schema-3 publication budget becomes a first-write concern.
    manifest, entries, payloads = _freeze_package(control_plane, package_dir, package_sha256)
    initial_gate = _validate_apply_gate(
        manifest,
        control_plane=control_plane,
        leaf_root=leaf_root,
        runtime_manifest=runtime_manifest.resolve(),
        adopt_dirty=adopt_dirty,
        network_timeout_seconds=timeout,
        require_target_preimages=True,
    )
    rendered_lock, rendered_agents = _render_from_payload(
        control_plane,
        payloads[".toplayer/repo.yaml"],
        payloads[".toplayer/local/AGENTS.project.md"],
    )
    expected_entries = {entry["path"]: entry for entry in entries}
    for logical_path, actual in ((".toplayer/render.lock.json", rendered_lock), ("AGENTS.md", rendered_agents)):
        expected = expected_entries[logical_path]
        if len(actual) != expected["bytes"] or sha256_bytes(actual) != expected["sha256"]:
            raise AdoptionError("package topctl rendered bytes mismatch")

    coordinator = LockCoordinator(leaf_root)
    try:
        acquired = coordinator.acquire(
            lock_kind="PATH_LOCK",
            task=task,
            owner=owner,
            ttl_seconds=path_lock_ttl_seconds,
            paths=[{"kind": "exact", "path": path} for path in TARGET_PATHS],
        )
    except LockError as error:
        raise AdoptionError(f"unable to acquire apply PATH_LOCK: {error}") from error

    lock = acquired["lock"]
    watchdog = _LockWatchdog(coordinator, lock, owner, path_lock_ttl_seconds)
    journal: _Journal | None = None
    broker: _MutationBroker | None = None
    backups: dict[str, bytes | None] = {}
    gate: LeafGate | None = None
    primary: Exception | None = None
    applied = False
    committed = False
    try:
        watchdog.start()
        # Recheck only the narrow semantic gate under PATH_LOCK.  This is not a
        # recursive dirty-tree snapshot and intentionally permits disjoint
        # concurrent dirty work to continue changing.
        watchdog.check_live()
        gate = _validate_apply_gate(
            manifest,
            control_plane=control_plane,
            leaf_root=leaf_root,
            runtime_manifest=runtime_manifest.resolve(),
            adopt_dirty=adopt_dirty,
            network_timeout_seconds=timeout,
            require_target_preimages=True,
        )
        if gate != initial_gate:
            raise AdoptionError("branch, staged-index, or target preimages changed before locked apply")
        schema3 = _read_schema3_publish_evidence(
            evidence_path=schema3_publish_evidence,
            evidence_sha256=schema3_publish_evidence_sha256,
            lease_id=schema3_publish_lease_id,
            owner=schema3_publish_owner,
            task=schema3_publish_task,
            expires_at=schema3_publish_expires_at,
            reserve_seconds=publish_reserve_seconds,
            manifest=manifest,
            gate=gate,
            now_fn=deadline_now_fn,
        )
        journal = _Journal(journal_dir)
        prepared = _journal_prepared(
            journal,
            manifest=manifest,
            package_sha256=package_sha256,
            gate=gate,
            schema3=schema3,
            lock=watchdog.lock,
            entries=entries,
            network_timeout_seconds=timeout,
        )
        expected_preimages = {entry["path"]: entry for entry in gate.target_preimages}
        for logical_path in TARGET_PATHS:
            target = _target_path(leaf_root, logical_path)
            with _pinned_ancestors(leaf_root, target):
                identity = _target_identity(leaf_root, logical_path)
                if identity != expected_preimages[logical_path]:
                    raise AdoptionError(f"target preimage changed before backup capture: {logical_path}")
                if identity["state"] == "ABSENT":
                    backup = None
                else:
                    backup = _read_regular_bound(target, f"target backup {logical_path}")
                if _payload_identity(logical_path, backup) != expected_preimages[logical_path]:
                    raise AdoptionError(f"target backup bytes do not match gate preimage: {logical_path}")
                _assert_target_matches(
                    leaf_root,
                    logical_path,
                    expected_preimages[logical_path],
                    phase="backup capture",
                )
                backups[logical_path] = backup
        broker = _MutationBroker(leaf_root, coordinator, journal)
        with broker:
            # This check is deliberately before the first mkdir so an expired or
            # foreign lock causes ABORTED_PREWRITE with no bootstrap scaffold.
            # Recheck the immutable schema-3 evidence here as well: backup
            # capture must not silently consume the caller's hard first-write
            # reserve before the first leaf mutation.
            _assert_schema3_first_write_budget(schema3, now_fn=deadline_now_fn)
            watchdog.check_live()
            _ensure_bootstrap_directories(
                leaf_root,
                broker,
                watchdog,
                schema3,
                schema3_now_fn=deadline_now_fn,
            )
            for logical_path in TARGET_PATHS:
                watchdog.check_live()
                _write_target(
                    leaf_root,
                    logical_path,
                    payloads[logical_path],
                    expected_preimage=expected_preimages[logical_path],
                    broker=broker,
                    watchdog=watchdog,
                    schema3=schema3,
                    schema3_now_fn=deadline_now_fn,
                )
            watchdog.check_live()
            _postcheck(
                gate,
                entries,
                leaf_root=leaf_root,
                network_timeout_seconds=timeout,
            )
            # Persist the immutable receipt while the strict PATH_LOCK is
            # still live.  If this external fsync fails, the generic failure
            # path can still perform its CAS rollback under the same lock;
            # releasing first would create an unsafe rollback window.
            _assert_schema3_deadline(
                schema3,
                phase="COMMITTED receipt",
                finalization=True,
                now_fn=deadline_now_fn,
            )
            watchdog.check_live()
            # No watchdog audit append may interleave with the three evidence
            # writes below.  Quiescing first performs one final strict renew,
            # joins the background thread, and leaves any runtime state record
            # ordered before the sealed COMMITTED journal entry.
            watchdog.quiesce_for_finalization()
            receipt = _write_committed_receipt(
                journal,
                package_sha256=package_sha256,
                entries=entries,
                gate=gate,
                broker=broker,
                prepared_entry_sha256=prepared["entry_sha256"],
            )
            committed = True
            _assert_schema3_deadline(
                schema3,
                phase="PATH_LOCK release",
                now_fn=deadline_now_fn,
            )
        watchdog.release()
        _assert_schema3_deadline(
            schema3,
            phase="APPLIED finalization",
            now_fn=deadline_now_fn,
        )
        applied = True
        return {
            "result": "APPLIED",
            "package_sha256": package_sha256,
            "outputs": [entry["path"] for entry in entries],
            "journal_sha256": receipt["journal_sha256"],
            "receipt_sha256": sha256_bytes(_require_regular_file(journal.receipt_path, "apply receipt")),
            "broker_non_target_successful_mutations": 0,
        }
    except AbortedPrewriteError as error:
        if broker is None or broker.successful_leaf_mutations == 0:
            primary = error
            _record_terminal(journal, "ABORTED_PREWRITE", error)
        elif broker.replaced_targets and gate is not None:
            try:
                with broker:
                    _restore(
                        leaf_root,
                        backups,
                        payloads,
                        broker.replaced_targets,
                        gate.target_preimages,
                        broker=broker,
                        watchdog=watchdog,
                    )
                    broker.assert_no_live_temporaries()
            except Exception as rollback_error:
                primary = PartialApplyError(
                    f"apply reached a mutation after prewrite abort and CAS rollback failed: {rollback_error}"
                )
                _record_terminal(journal, "PARTIAL_APPLY", primary)
            else:
                primary = FailedRolledBackError(
                    f"apply failed after target mutation and rolled back: {error}"
                )
                _record_terminal(journal, "FAILED_ROLLED_BACK", primary)
        else:
            primary = PartialApplyError(f"apply failed after bootstrap mutation: {error}")
            _record_terminal(journal, "PARTIAL_APPLY", primary)
    except LockContinuityError as error:
        if committed:
            # The four target bytes and immutable receipt are already durable.
            # Do not overwrite them after a final lock-continuity gap; the
            # stale receipt intentionally becomes non-validating once this
            # terminal marker is appended.
            primary = PartialApplyError(
                f"apply committed target bytes but PATH_LOCK finalization failed: {error}"
            )
            _record_terminal(journal, "PARTIAL_APPLY", primary)
        elif broker is None or broker.successful_leaf_mutations == 0:
            primary = AbortedPrewriteError(str(error))
            _record_terminal(journal, "ABORTED_PREWRITE", primary)
        else:
            primary = error
            _record_terminal(journal, "PARTIAL_APPLY", error)
    except Exception as error:
        if committed:
            # See the LockContinuityError branch above.  Once COMMITTED is
            # durable, any later finalization error is fail-closed PARTIAL and
            # never starts a second target-writing transaction.
            primary = PartialApplyError(
                f"apply committed target bytes but finalization failed: {error}"
            )
            _record_terminal(journal, "PARTIAL_APPLY", primary)
        elif broker is not None and broker.replaced_targets and gate is not None:
            try:
                with broker:
                    _restore(
                        leaf_root,
                        backups,
                        payloads,
                        broker.replaced_targets,
                        gate.target_preimages,
                        broker=broker,
                        watchdog=watchdog,
                    )
                    broker.assert_no_live_temporaries()
            except LockContinuityError as rollback_gap:
                primary = rollback_gap
                _record_terminal(journal, "PARTIAL_APPLY", rollback_gap)
            except Exception as rollback_error:
                primary = PartialApplyError(
                    f"apply failed after {error} and CAS rollback failed: {rollback_error}"
                )
                _record_terminal(journal, "PARTIAL_APPLY", primary)
            else:
                primary = FailedRolledBackError(f"apply failed and rolled back: {error}")
                _record_terminal(journal, "FAILED_ROLLED_BACK", primary)
        elif broker is not None and broker.successful_leaf_mutations:
            primary = PartialApplyError(f"apply failed after bootstrap mutation: {error}")
            _record_terminal(journal, "PARTIAL_APPLY", primary)
        else:
            primary = AbortedPrewriteError(f"apply failed before any leaf mutation: {error}")
            _record_terminal(journal, "ABORTED_PREWRITE", primary)
    finally:
        watchdog.stop()
        if not applied:
            try:
                current = watchdog.lock
                released = coordinator.release(
                    lock_id=current["lock_id"], owner=owner, nonce=current["nonce"]
                )
                if released.get("observed_state") != "ACTIVE" and primary is None:
                    primary = PartialApplyError("apply PATH_LOCK was not active when released")
            except LockError as error:
                if primary is None:
                    primary = PartialApplyError(f"apply PATH_LOCK release failed: {error}")
    if primary is None:
        raise PartialApplyError("apply ended without a classified result")
    raise primary


def _load_journal(
    directory: Path,
    *,
    expected_journal_sha256: str,
    expected_receipt_sha256: str,
) -> tuple[list[dict[str, Any]], str, dict[str, Any], str]:
    """Anchor raw bytes before parsing either mutually-rewritable document."""

    journal_path = directory / JOURNAL_FILE
    receipt_path = directory / RECEIPT_FILE
    raw = _require_regular_file(journal_path, "apply journal")
    receipt_raw = _require_regular_file(receipt_path, "apply receipt")
    journal_sha256 = sha256_bytes(raw)
    receipt_sha256 = sha256_bytes(receipt_raw)
    if journal_sha256 != expected_journal_sha256:
        raise AdoptionError("external expected journal SHA-256 anchor mismatch")
    if receipt_sha256 != expected_receipt_sha256:
        raise AdoptionError("external expected receipt SHA-256 anchor mismatch")
    try:
        receipt = json.loads(receipt_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdoptionError("apply receipt is invalid JSON") from error
    entries: list[dict[str, Any]] = []
    previous = "0" * 64
    for sequence, line in enumerate(raw.splitlines()):
        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdoptionError("apply journal contains invalid JSON") from error
        if not isinstance(entry, dict) or entry.get("sequence") != sequence:
            raise AdoptionError("apply journal sequence is invalid")
        digest = entry.get("entry_sha256")
        body = dict(entry)
        body.pop("entry_sha256", None)
        if (
            not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
            or body.get("previous_entry_sha256") != previous
            or sha256_bytes(canonical_json_bytes(body)) != digest
        ):
            raise AdoptionError("apply journal hash chain is invalid")
        previous = digest
        entries.append(entry)
    if not entries or entries[0].get("event") != "PREPARED":
        raise AdoptionError("apply journal has no PREPARED entry")
    if not any(entry.get("event") == "COMMITTED" for entry in entries):
        raise AdoptionError("apply journal has no COMMITTED entry")
    return entries, journal_sha256, receipt, receipt_sha256


_TEMPORARY_LOGICAL_RE = re.compile(r"^\.adoptctl-[0-9a-f]{32}\.tmp$")
_RUNTIME_LOGICAL_RE = re.compile(
    r"^\.git/toplayer-runtime/leases-v1/(?:state\.lock|state\.json|state\.json\.tmp\.[1-9][0-9]*\.[0-9a-f]{32})$"
)


def _is_journal_temporary(path: object) -> bool:
    """Recognize only the same-directory temporary names the broker emits."""

    if not isinstance(path, str):
        return False
    try:
        canonical = _canonical_path(path, "journal temporary path")
    except AdoptionError:
        return False
    parsed = PurePosixPath(canonical)
    parent = "" if parsed.parent == PurePosixPath(".") else parsed.parent.as_posix()
    return parent in {"", ".toplayer", ".toplayer/local"} and bool(
        _TEMPORARY_LOGICAL_RE.fullmatch(parsed.name)
    )


def _is_runtime_logical_path(path: object) -> bool:
    if not isinstance(path, str):
        return False
    try:
        return bool(_RUNTIME_LOGICAL_RE.fullmatch(_canonical_path(path, "PATH_LOCK journal path")))
    except AdoptionError:
        return False


def _mutation_key(
    operation: object,
    audit_event: object,
    paths: object,
) -> tuple[str, str, tuple[str, ...]]:
    expected_audit = {
        "mkdir": "os.mkdir",
        "temp_create": "open",
        "replace_target": "os.rename",
        "temp_unlink": "os.remove",
    }
    if (
        not isinstance(operation, str)
        or operation not in expected_audit
        or audit_event != expected_audit[operation]
        or not isinstance(paths, list)
        or not paths
        or not all(isinstance(path, str) for path in paths)
    ):
        raise AdoptionError("journal mutation record is invalid")
    canonical_paths = tuple(_canonical_path(path, "journal mutation path") for path in paths)
    if operation == "mkdir":
        if canonical_paths not in {(".toplayer",), (".toplayer/local",)}:
            raise AdoptionError("journal bootstrap mkdir escapes closure")
    elif operation == "temp_create":
        if len(canonical_paths) != 1 or not _is_journal_temporary(canonical_paths[0]):
            raise AdoptionError("journal temporary creation escapes closure")
    elif operation == "replace_target":
        if (
            len(canonical_paths) != 2
            or not _is_journal_temporary(canonical_paths[0])
            or canonical_paths[1] not in TARGET_PATHS
            or PurePosixPath(canonical_paths[0]).parent
            != PurePosixPath(canonical_paths[1]).parent
        ):
            raise AdoptionError("journal target replacement escapes closure")
    elif operation == "temp_unlink":
        if len(canonical_paths) != 1 or not _is_journal_temporary(canonical_paths[0]):
            raise AdoptionError("journal temporary finalizer escapes closure")
    return operation, expected_audit[operation], canonical_paths


def _increment(counter: dict[tuple[str, str, tuple[str, ...]], int], key: tuple[str, str, tuple[str, ...]]) -> None:
    counter[key] = counter.get(key, 0) + 1


def _decrement(
    counter: dict[tuple[str, str, tuple[str, ...]], int],
    key: tuple[str, str, tuple[str, ...]],
    *,
    message: str,
) -> None:
    current = counter.get(key, 0)
    if current < 1:
        raise AdoptionError(message)
    if current == 1:
        del counter[key]
    else:
        counter[key] = current - 1


def _validate_journal_mutation_closure(
    entries: list[dict[str, Any]],
    *,
    prepared: dict[str, Any],
) -> None:
    """Validate the released broker's journaled, closed writer protocol.

    This is a semantic validator for the released writer protocol, not an OS
    audit oracle.  It requires every leaf ``AUDIT_ALLOWED`` record to close an
    already-pending mutation intent with the same operation, audit event, and
    canonical logical path tuple.
    """

    if entries[0].get("event") != "PREPARED" or sum(
        entry.get("event") == "PREPARED" for entry in entries
    ) != 1:
        raise AdoptionError("apply journal must begin with one PREPARED entry")
    if entries[-1].get("event") != "COMMITTED" or sum(
        entry.get("event") == "COMMITTED" for entry in entries
    ) != 1:
        raise AdoptionError("apply journal must end in one COMMITTED entry")
    expected_env_sha256 = prepared.get("git_sanitized_env_sha256")
    if not isinstance(expected_env_sha256, str) or not SHA256_RE.fullmatch(expected_env_sha256):
        raise AdoptionError("journal PREPARED Git environment binding is invalid")
    pending: dict[tuple[str, str, tuple[str, ...]], int] = {}
    audited_pending: dict[tuple[str, str, tuple[str, ...]], int] = {}
    created_temporaries: set[str] = set()
    replaced_temporaries: set[str] = set()
    replaced_targets: set[str] = set()
    created_directories: set[str] = set()
    permitted_events = {
        "PREPARED",
        "COMMITTED",
        "AUDIT_ALLOWED",
        "MUTATION_INTENT",
        "MUTATION_RESULT",
    }
    for entry in entries:
        event = entry.get("event")
        if event not in permitted_events:
            raise AdoptionError("completed apply journal contains a non-success terminal or rejected event")
        if event == "AUDIT_ALLOWED":
            scope = entry.get("scope")
            audit_event = entry.get("audit_event")
            paths = entry.get("paths")
            if scope in {"read_only_git", "lock_read_only_git"}:
                command = entry.get("logical_command")
                expected_environment = (prepared.get("lock_git_sanitized_env_sha256")
                    if scope == "lock_read_only_git" else expected_env_sha256)
                if (
                    audit_event != "subprocess.Popen"
                    or not isinstance(command, list)
                    or not all(isinstance(item, str) for item in command)
                    or not isinstance(expected_environment, str)
                    or not SHA256_RE.fullmatch(expected_environment)
                    or not (tuple(command) in lock_core._READ_ONLY_GIT_COMMANDS
                            if scope == "lock_read_only_git" else _allowed_readonly_git_command(tuple(command)))
                    or entry.get("sanitized_env_sha256") != expected_environment
                ):
                    raise AdoptionError("journal read-only Git audit record is invalid")
            elif scope == "path_lock_runtime":
                if (
                    audit_event not in {"open", "os.rename", "os.remove"}
                    or not isinstance(paths, list)
                    or not paths
                    or not all(_is_runtime_logical_path(path) for path in paths)
                ):
                    raise AdoptionError("journal PATH_LOCK runtime audit record is invalid")
            elif scope == "leaf_closed_writer":
                key = _mutation_key(
                    {
                        "os.mkdir": "mkdir",
                        "open": "temp_create",
                        "os.rename": "replace_target",
                        "os.remove": "temp_unlink",
                    }.get(audit_event),
                    audit_event,
                    paths,
                )
                if pending.get(key, 0) <= audited_pending.get(key, 0):
                    raise AdoptionError("journal leaf audit permission lacks a pending exact mutation intent")
                _increment(audited_pending, key)
            else:
                raise AdoptionError("journal contains an unknown audit permission")
            continue
        if event == "MUTATION_INTENT":
            _increment(
                pending,
                _mutation_key(entry.get("operation"), entry.get("audit_event"), entry.get("paths")),
            )
            continue
        if event != "MUTATION_RESULT":
            continue
        if entry.get("success") is not True:
            raise AdoptionError("completed journal mutation result is invalid")
        mutation = _mutation_key(
            entry.get("operation"), entry.get("audit_event"), entry.get("paths")
        )
        _decrement(pending, mutation, message="journal mutation result lacks a matching intent")
        _decrement(
            audited_pending,
            mutation,
            message="journal mutation result lacks a matching leaf audit permission",
        )
        operation, _, paths = mutation
        if operation == "mkdir":
            if paths[0] in created_directories:
                raise AdoptionError("journal bootstrap mkdir is duplicated")
            created_directories.add(paths[0])
        elif operation == "temp_create":
            if paths[0] in created_temporaries:
                raise AdoptionError("journal temporary creation is duplicated")
            created_temporaries.add(paths[0])
        elif operation == "replace_target":
            temporary, target = paths
            if (
                temporary not in created_temporaries
                or temporary in replaced_temporaries
                or target in replaced_targets
            ):
                raise AdoptionError("journal target replacement sequence is invalid")
            replaced_temporaries.add(temporary)
            replaced_targets.add(target)
        elif operation == "temp_unlink":
            # A successfully committed apply should have consumed each temp in
            # os.replace; unlink is only a failure-path finalizer.
            raise AdoptionError("completed journal unexpectedly unlinked a temporary")
    if pending or audited_pending:
        raise AdoptionError("journal mutation intent has no matching result")
    if (
        created_directories != {".toplayer", ".toplayer/local"}
        or replaced_targets != set(TARGET_PATHS)
        or replaced_temporaries != created_temporaries
    ):
        raise AdoptionError("journal does not prove one atomic replacement for every target")


def _validate_apply_evidence(
    *,
    control_plane: Path,
    leaf_root: Path,
    package_dir: Path,
    package_sha256: str,
    runtime_manifest: Path,
    journal_dir: Path,
    expected_journal_sha256: str,
    expected_receipt_sha256: str,
    network_timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> ApplyEvidence:
    """Validate immutable package and apply evidence without a live-state gate."""

    for label, value in (
        ("package", package_sha256),
        ("expected journal", expected_journal_sha256),
        ("expected receipt", expected_receipt_sha256),
    ):
        if not SHA256_RE.fullmatch(value):
            raise AdoptionError(f"{label} SHA-256 is invalid")
    control_plane = control_plane.resolve()
    leaf_root = leaf_root.resolve()
    _assert_runtime_isolated(control_plane, leaf_root, runtime_manifest)
    journal_dir = journal_dir.absolute()
    if _within(journal_dir, control_plane) or _within(journal_dir, leaf_root):
        raise AdoptionError("journal directory must remain outside repositories")
    entries, journal_sha256, receipt, receipt_sha256 = _load_journal(
        journal_dir,
        expected_journal_sha256=expected_journal_sha256,
        expected_receipt_sha256=expected_receipt_sha256,
    )
    journal_schema = json.loads(
        _require_regular_file(
            control_plane / "schemas" / "leaf_first_adoption_journal.schema.json",
            "control apply journal schema",
        ).decode("utf-8")
    )
    try:
        entry_schema = {"$ref": "#/$defs/entry", "$defs": journal_schema["$defs"]}
        receipt_schema = {"$ref": "#/$defs/receipt", "$defs": journal_schema["$defs"]}
        entry_validator = jsonschema.Draft202012Validator(entry_schema)
        for entry in entries:
            entry_validator.validate(entry)
        jsonschema.Draft202012Validator(receipt_schema).validate(receipt)
    except (KeyError, jsonschema.ValidationError, jsonschema.SchemaError) as error:
        raise AdoptionError("apply journal schema validation failed") from error
    required_receipt = {
        "schema_version",
        "kind",
        "result",
        "package_sha256",
        "journal_file",
        "journal_sha256",
        "prepared_entry_sha256",
        "committed_entry_sha256",
        "outputs",
        "four_postimages",
        "staged_index",
        "broker_non_target_successful_mutations",
    }
    if not isinstance(receipt, dict) or set(receipt) != required_receipt:
        raise AdoptionError("apply receipt envelope is invalid")
    if (
        receipt["schema_version"] != 1
        or receipt["kind"] != "leaf_first_adoption_apply_receipt"
        or receipt["result"] != "APPLIED"
        or receipt["package_sha256"] != package_sha256
        or receipt["journal_file"] != JOURNAL_FILE
        or receipt["journal_sha256"] != journal_sha256
        or receipt["broker_non_target_successful_mutations"] != 0
    ):
        raise AdoptionError("apply receipt binding is invalid")
    prepared = entries[0]
    committed = [entry for entry in entries if entry.get("event") == "COMMITTED"][-1]
    _validate_journal_mutation_closure(entries, prepared=prepared)
    if (
        committed.get("broker_non_target_successful_mutations") != 0
        or receipt["broker_non_target_successful_mutations"]
        != committed.get("broker_non_target_successful_mutations")
    ):
        raise AdoptionError("journal reports a broker non-target successful mutation")
    manifest, package_entries, payloads = _freeze_package(control_plane, package_dir, package_sha256)
    leaf_manifest = manifest["leaf"]
    if (
        prepared.get("package_sha256") != package_sha256
        or prepared.get("control_release") != manifest["control_release"]
        or prepared.get("runtime") != manifest["runtime"]
        or prepared.get("manifest_leaf_identity") != leaf_manifest["identity"]
        or prepared.get("leaf_identity") != leaf_manifest["identity"]
        or prepared.get("manifest_target_preimages") != leaf_manifest["target_preimages"]
        or prepared.get("target_preimages") != leaf_manifest["target_preimages"]
    ):
        raise AdoptionError("journal release or runtime binding changed")
    schema3 = prepared.get("schema3_publish")
    if not isinstance(schema3, dict) or set(schema3) != {
        "sha256",
        "lease_id",
        "owner",
        "task",
        "state",
        "issued_at",
        "expires_at",
        "ttl_seconds",
        "shared_paths",
        "reserve_seconds",
        "adapter_id",
        "adapter_version",
        "repo_id",
        "leaf_origin_sha256",
        "leaf_identity",
        "target_preimages",
        "registry_state_sha256",
    }:
        raise AdoptionError("journal schema3 evidence binding is invalid")
    if (
        not all(isinstance(schema3.get(field), str) and schema3[field] for field in ("lease_id", "owner", "task"))
        or schema3.get("state") != "ACTIVE"
        or schema3.get("adapter_id") != SCHEMA3_ADAPTER_ID
        or schema3.get("adapter_version") != SCHEMA3_ADAPTER_VERSION
        or schema3.get("repo_id") != leaf_manifest["repo_id"]
        or schema3.get("leaf_origin_sha256") != leaf_manifest["remote_sha256"]
        or schema3.get("leaf_identity") != leaf_manifest["identity"]
        or schema3.get("target_preimages") != leaf_manifest["target_preimages"]
        or not all(
            isinstance(schema3.get(field), str) and SHA256_RE.fullmatch(schema3[field])
            for field in ("sha256", "registry_state_sha256")
        )
    ):
        raise AdoptionError("journal schema3 evidence does not bind this package leaf")
    try:
        issued = _parse_timestamp(schema3["issued_at"], "journal schema3 issued_at")
        expiry = _parse_timestamp(schema3["expires_at"], "journal schema3 expires_at")
    except (KeyError, TypeError) as error:
        raise AdoptionError("journal schema3 evidence timestamps are invalid") from error
    if (
        isinstance(schema3.get("ttl_seconds"), bool)
        or not isinstance(schema3.get("ttl_seconds"), int)
        or expiry != issued + timedelta(seconds=schema3["ttl_seconds"])
        or isinstance(schema3.get("reserve_seconds"), bool)
        or not isinstance(schema3.get("reserve_seconds"), int)
        or schema3["reserve_seconds"] < MIN_PUBLISH_RESERVE_SECONDS
        or schema3.get("shared_paths") != ["AGENTS.md"]
    ):
        raise AdoptionError("journal schema3 evidence timing or reserve binding is invalid")
    path_lock = prepared.get("path_lock")
    required_lock = {
        "lock_id",
        "owner",
        "task",
        "acquired_at",
        "expires_at",
        "ttl_seconds",
        "nonce_sha256",
        "paths",
    }
    if (
        not isinstance(path_lock, dict)
        or set(path_lock) != required_lock
        or not all(isinstance(path_lock.get(field), str) and path_lock[field] for field in required_lock - {"ttl_seconds", "paths"})
        or isinstance(path_lock.get("ttl_seconds"), bool)
        or not isinstance(path_lock.get("ttl_seconds"), int)
        or path_lock["ttl_seconds"] < 1
        or not isinstance(path_lock.get("nonce_sha256"), str)
        or not SHA256_RE.fullmatch(path_lock["nonce_sha256"])
        or not isinstance(path_lock.get("paths"), list)
        or len(path_lock["paths"]) != len(TARGET_PATHS)
        or {
            (entry.get("kind"), entry.get("path"))
            for entry in path_lock["paths"]
            if isinstance(entry, dict) and set(entry) == {"kind", "path"}
        }
        != {("exact", path) for path in TARGET_PATHS}
    ):
        raise AdoptionError("journal PATH_LOCK binding is invalid")
    try:
        lock_issued = _parse_timestamp(
            path_lock["acquired_at"],
            "journal PATH_LOCK acquired_at",
            allow_fractional=False,
        )
        lock_expiry = _parse_timestamp(
            path_lock["expires_at"],
            "journal PATH_LOCK expires_at",
            allow_fractional=False,
        )
    except (KeyError, TypeError) as error:
        raise AdoptionError("journal PATH_LOCK timestamps are invalid") from error
    if lock_expiry != lock_issued + timedelta(seconds=path_lock["ttl_seconds"]):
        raise AdoptionError("journal PATH_LOCK TTL binding is invalid")
    if (
        prepared.get("outputs") != package_entries
        or committed.get("package_sha256") != package_sha256
        or committed.get("outputs") != package_entries
        or committed.get("four_postimages") != package_entries
        or receipt["outputs"] != committed.get("outputs")
        or receipt["four_postimages"] != committed.get("four_postimages")
        or receipt["prepared_entry_sha256"] != prepared.get("entry_sha256")
        or committed.get("prepared_entry_sha256") != prepared.get("entry_sha256")
        or receipt["committed_entry_sha256"] != committed.get("entry_sha256")
        or receipt_sha256 != expected_receipt_sha256
    ):
        raise AdoptionError("journal or receipt output binding changed")
    if (
        committed.get("staged_index") != prepared.get("staged_index")
        or receipt["staged_index"] != committed.get("staged_index")
    ):
        raise AdoptionError("journal staged-index mirror changed")
    return ApplyEvidence(
        manifest=manifest,
        package_entries=package_entries,
        payloads=payloads,
        prepared=prepared,
        journal_sha256=journal_sha256,
        receipt_sha256=receipt_sha256,
    )


def validate_apply(
    *,
    control_plane: Path,
    leaf_root: Path,
    package_dir: Path,
    package_sha256: str,
    runtime_manifest: Path,
    journal_dir: Path,
    expected_journal_sha256: str,
    expected_receipt_sha256: str,
    network_timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Validate anchored apply evidence and the stage-bound live post-state."""

    evidence = _validate_apply_evidence(
        control_plane=control_plane,
        leaf_root=leaf_root,
        package_dir=package_dir,
        package_sha256=package_sha256,
        runtime_manifest=runtime_manifest,
        journal_dir=journal_dir,
        expected_journal_sha256=expected_journal_sha256,
        expected_receipt_sha256=expected_receipt_sha256,
        network_timeout_seconds=network_timeout_seconds,
    )
    control_plane = control_plane.resolve()
    leaf_root = leaf_root.resolve()
    leaf_manifest = evidence.manifest["leaf"]
    current = _static_leaf_identity(leaf_root, _network_timeout(network_timeout_seconds))
    if current != evidence.prepared.get("leaf_identity") or current != leaf_manifest["identity"]:
        raise AdoptionError("validator observed leaf HEAD, tree, origin, or worktree drift")
    index = _staged_index_identity(leaf_root)
    if index != evidence.prepared.get("staged_index") or not index["clean"]:
        raise AdoptionError("validator observed staged-index drift")
    expected = {entry["path"]: entry for entry in evidence.package_entries}
    for logical_path in TARGET_PATHS:
        actual = _target_identity(leaf_root, logical_path)
        if actual != {
            "path": logical_path,
            "state": "PRESENT",
            "bytes": expected[logical_path]["bytes"],
            "sha256": expected[logical_path]["sha256"],
        }:
            raise AdoptionError("validator observed target-byte drift")
    lock, rendered = _render_from_payload(
        control_plane,
        evidence.payloads[".toplayer/repo.yaml"],
        evidence.payloads[".toplayer/local/AGENTS.project.md"],
    )
    for logical_path, actual in ((".toplayer/render.lock.json", lock), ("AGENTS.md", rendered)):
        expected_entry = expected[logical_path]
        if len(actual) != expected_entry["bytes"] or sha256_bytes(actual) != expected_entry["sha256"]:
            raise AdoptionError("validator observed deterministic render drift")
    return {
        "result": "PASS",
        "package_sha256": package_sha256,
        "journal_sha256": evidence.journal_sha256,
        "receipt_sha256": evidence.receipt_sha256,
        "outputs": list(TARGET_PATHS),
    }


def _publication_git(
    root: Path,
    reason_code: str,
    *arguments: str,
    timeout_seconds: int = 60,
) -> str:
    try:
        return _git(root, *arguments, timeout_seconds=timeout_seconds)
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError(reason_code) from error


def _publication_git_bytes(
    root: Path,
    reason_code: str,
    *arguments: str,
    timeout_seconds: int = 60,
) -> bytes:
    try:
        return _git_bytes(root, *arguments, timeout_seconds=timeout_seconds)
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError(reason_code) from error


def verify_publication(
    *,
    control_plane: Path,
    leaf_root: Path,
    package_dir: Path,
    package_sha256: str,
    runtime_manifest: Path,
    journal_dir: Path,
    expected_journal_sha256: str,
    expected_receipt_sha256: str,
    expected_publication_commit: str,
    network_timeout_seconds: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Verify an exact-four publication without weakening stage-bound validation."""

    if not OID_RE.fullmatch(expected_publication_commit):
        raise PublicationVerificationError("PUBLICATION_HEAD_MISMATCH")
    try:
        runtime_identity = _validate_runtime_manifest(runtime_manifest)
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError("RUNTIME_IDENTITY_MISMATCH") from error
    try:
        evidence = _validate_apply_evidence(
            control_plane=control_plane,
            leaf_root=leaf_root,
            package_dir=package_dir,
            package_sha256=package_sha256,
            runtime_manifest=runtime_manifest,
            journal_dir=journal_dir,
            expected_journal_sha256=expected_journal_sha256,
            expected_receipt_sha256=expected_receipt_sha256,
            network_timeout_seconds=network_timeout_seconds,
        )
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError("APPLY_EVIDENCE_INVALID") from error

    control_plane = control_plane.resolve()
    leaf_root = leaf_root.resolve()
    try:
        if _git_root(leaf_root) != leaf_root:
            raise AdoptionError("leaf root mismatch")
        worktree_count = _worktree_count(leaf_root)
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError("PUBLICATION_WORKTREE_DRIFT") from error
    if worktree_count != 1:
        raise PublicationVerificationError("PUBLICATION_WORKTREE_DRIFT")

    package_identity = evidence.manifest["leaf"]["identity"]
    branch = _publication_git(
        leaf_root,
        "PUBLICATION_HEAD_MISMATCH",
        "symbolic-ref",
        "--quiet",
        "--short",
        "HEAD",
    )
    if branch != "main" or branch != package_identity.get("branch"):
        raise PublicationVerificationError("PUBLICATION_HEAD_MISMATCH")
    head = _publication_git(leaf_root, "PUBLICATION_HEAD_MISMATCH", "rev-parse", "HEAD")
    resolved_commit = _publication_git(
        leaf_root,
        "PUBLICATION_HEAD_MISMATCH",
        "rev-parse",
        "--verify",
        f"{expected_publication_commit}^{{commit}}",
    )
    if head != expected_publication_commit or resolved_commit != expected_publication_commit:
        raise PublicationVerificationError("PUBLICATION_HEAD_MISMATCH")

    try:
        origin = _remote(leaf_root)
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError("PUBLICATION_ORIGIN_MISMATCH") from error
    origin_sha256 = sha256_bytes(origin.encode("utf-8"))
    if origin_sha256 != evidence.manifest["leaf"].get("remote_sha256"):
        raise PublicationVerificationError("PUBLICATION_ORIGIN_MISMATCH")

    upstream_ref = _publication_git(
        leaf_root,
        "PUBLICATION_REMOTE_DIVERGENCE",
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
    )
    upstream = _publication_git(
        leaf_root,
        "PUBLICATION_REMOTE_DIVERGENCE",
        "rev-parse",
        "@{upstream}",
    )
    if upstream_ref != "origin/main" or upstream != expected_publication_commit:
        raise PublicationVerificationError("PUBLICATION_REMOTE_DIVERGENCE")
    try:
        remote_output = _git(
            leaf_root,
            "ls-remote",
            "origin",
            "refs/heads/main",
            timeout_seconds=_network_timeout(network_timeout_seconds),
        )
    except (AdoptionError, OSError, ValueError) as error:
        raise PublicationVerificationError("PUBLICATION_REMOTE_UNAVAILABLE") from error
    remote_rows = [line.split("\t") for line in remote_output.splitlines() if line]
    if (
        len(remote_rows) != 1
        or len(remote_rows[0]) != 2
        or remote_rows[0][1] != "refs/heads/main"
        or remote_rows[0][0] != expected_publication_commit
    ):
        raise PublicationVerificationError("PUBLICATION_REMOTE_DIVERGENCE")

    parent_row = _publication_git(
        leaf_root,
        "PUBLICATION_PARENT_MISMATCH",
        "rev-list",
        "--parents",
        "-n",
        "1",
        expected_publication_commit,
    ).split()
    if len(parent_row) != 2 or parent_row[0] != expected_publication_commit:
        raise PublicationVerificationError("PUBLICATION_PARENT_MISMATCH")
    parent = parent_row[1]
    if parent != package_identity.get("head"):
        raise PublicationVerificationError("PUBLICATION_PARENT_MISMATCH")
    parent_tree = _publication_git(
        leaf_root,
        "PUBLICATION_PARENT_TREE_MISMATCH",
        "rev-parse",
        f"{parent}^{{tree}}",
    )
    if parent_tree != package_identity.get("tree"):
        raise PublicationVerificationError("PUBLICATION_PARENT_TREE_MISMATCH")

    changed_raw = _publication_git_bytes(
        leaf_root,
        "PUBLICATION_PATHSET_MISMATCH",
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "-z",
        parent,
        expected_publication_commit,
    )
    try:
        changed_paths = [
            _canonical_path(value.decode("utf-8", "strict"), "publication path")
            for value in changed_raw.split(b"\0")
            if value
        ]
    except (UnicodeDecodeError, AdoptionError) as error:
        raise PublicationVerificationError("PUBLICATION_PATHSET_MISMATCH") from error
    if len(changed_paths) != len(TARGET_PATHS) or set(changed_paths) != set(TARGET_PATHS):
        raise PublicationVerificationError("PUBLICATION_PATHSET_MISMATCH")

    expected_outputs = {entry["path"]: entry for entry in evidence.package_entries}
    for logical_path in TARGET_PATHS:
        committed_payload = _publication_git_bytes(
            leaf_root,
            "PUBLICATION_BLOB_MISMATCH",
            "show",
            f"{expected_publication_commit}:{logical_path}",
        )
        output = expected_outputs[logical_path]
        if (
            len(committed_payload) != output["bytes"]
            or sha256_bytes(committed_payload) != output["sha256"]
        ):
            raise PublicationVerificationError("PUBLICATION_BLOB_MISMATCH")

    staged = _publication_git_bytes(
        leaf_root,
        "PUBLICATION_INDEX_OR_UNMERGED",
        "diff",
        "--cached",
        "--raw",
        "-z",
        "--full-index",
    )
    unmerged = _publication_git_bytes(
        leaf_root,
        "PUBLICATION_INDEX_OR_UNMERGED",
        "ls-files",
        "-u",
        "-z",
    )
    if staged or unmerged:
        raise PublicationVerificationError("PUBLICATION_INDEX_OR_UNMERGED")

    status_raw = _publication_git_bytes(
        leaf_root,
        "PUBLICATION_TARGET_DIRTY",
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    try:
        status_records = _parse_status_payload(status_raw)
    except AdoptionError as error:
        raise PublicationVerificationError("PUBLICATION_TARGET_DIRTY") from error
    if any(
        path in TARGET_PATHS
        for record in status_records
        for path in record["paths"]
    ):
        raise PublicationVerificationError("PUBLICATION_TARGET_DIRTY")
    for logical_path in TARGET_PATHS:
        try:
            actual = _target_identity(leaf_root, logical_path)
        except (AdoptionError, OSError, ValueError) as error:
            raise PublicationVerificationError("PUBLICATION_TARGET_DIRTY") from error
        output = expected_outputs[logical_path]
        if actual != {
            "path": logical_path,
            "state": "PRESENT",
            "bytes": output["bytes"],
            "sha256": output["sha256"],
        }:
            raise PublicationVerificationError("PUBLICATION_TARGET_DIRTY")

    publication_tree = _publication_git(
        leaf_root,
        "PUBLICATION_HEAD_MISMATCH",
        "rev-parse",
        f"{expected_publication_commit}^{{tree}}",
    )
    return {
        "result": "VERIFIED_PUBLICATION",
        "runtime": runtime_identity,
        "package_sha256": package_sha256,
        "journal_sha256": evidence.journal_sha256,
        "receipt_sha256": evidence.receipt_sha256,
        "publication": {
            "branch": branch,
            "commit": expected_publication_commit,
            "tree": publication_tree,
            "parent": parent,
            "parent_tree": parent_tree,
            "path_count": len(changed_paths),
            "outputs": evidence.package_entries,
            "origin_sha256": origin_sha256,
            "upstream_ref": upstream_ref,
            "upstream_commit": upstream,
            "live_main": remote_rows[0][0],
            "worktree_count": worktree_count,
        },
        "non_target_status": {
            "count": len(status_records),
            "bytes": len(status_raw),
            "sha256": sha256_bytes(status_raw),
        },
    }
