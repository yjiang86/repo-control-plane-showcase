from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import time
from typing import Any, Callable, Iterator
import unicodedata
import uuid


LOCK_KINDS = {"PATH_LOCK", "GIT_MUTATION_LOCK"}
LEGACY_LOCK_ALIASES = {
    "PROJECT_PATH_LEASE": "PATH_LOCK",
    "GIT_PUBLICATION_LEASE": "GIT_MUTATION_LOCK",
}
RETIRED_AUTHORITY_LEASE_CLASSES = {
    "HOT_STATE_LEASE",
    "SHARED_CORE_LEASE",
    "FIRST_REBIND_LEASE",
    "RELEASE_REBIND_LEASE",
    "PAUSED_ZERO_GRANT_REBIND_LEASE",
}
STATE_SCHEMA_VERSION = 2
COORDINATION_SCOPE = "single_host_single_git_common_dir"
MAX_TTL_SECONDS = 86400
MAX_GIT_MUTATION_TTL_SECONDS = 900
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
GIT_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")
WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS = (0.01, 0.025, 0.05, 0.1, 0.2)
WINDOWS_RESERVED_PATH_NAMES = {
    "aux",
    "con",
    "conin$",
    "conout$",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class LockError(ValueError):
    """A deterministic coordination-lock validation or conflict error."""


class LockUnavailable(LockError):
    """The OS lock primitive failed for a reason other than another holder."""


class LockConflict(LockError):
    """A valid competing lock requires wait, coordination, or handoff."""


# Compatibility imports for callers that used the old module names. These are
# names only; the grant/authority semantics were intentionally retired.
LeaseError = LockError


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise LockError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise LockError(f"{label} must be a UTC timestamp") from error
    return parsed.replace(tzinfo=timezone.utc)


def require_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or CONTROL_CHARACTER_PATTERN.search(value)
    ):
        raise LockError(f"{label} must be non-empty printable text")
    return value


def require_git_oid(value: Any, label: str = "base_head") -> str:
    if not isinstance(value, str) or not GIT_OID_PATTERN.fullmatch(value):
        raise LockError(f"{label} must be a lowercase Git object ID")
    return value


def require_ttl(value: Any, *, maximum: int = MAX_TTL_SECONDS) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > maximum
    ):
        raise LockError(
            f"ttl_seconds must be between 1 and {maximum}"
        )
    return value


def canonical_lock_kind(value: Any) -> str:
    kind = require_text(value, "lock_kind")
    if kind in LEGACY_LOCK_ALIASES:
        return LEGACY_LOCK_ALIASES[kind]
    if kind in RETIRED_AUTHORITY_LEASE_CLASSES:
        raise LockError(
            f"{kind} is retired; dynamic locks coordinate concurrency and do not "
            "provide grant, rebind, or publication authority"
        )
    if kind not in LOCK_KINDS:
        raise LockError(f"unsupported lock_kind: {kind}")
    return kind


def normalize_repo_path(value: Any, label: str = "path") -> str:
    if not isinstance(value, str) or not value:
        raise LockError(f"{label} must be a non-empty repository-relative path")
    if CONTROL_CHARACTER_PATTERN.search(value):
        raise LockError(f"{label} contains a control character")
    if value.startswith(("\\\\", "//")) or WINDOWS_DRIVE_PATTERN.match(value):
        raise LockError(f"{label} must not be UNC, absolute, or drive-qualified")
    normalized = unicodedata.normalize("NFC", value.replace("\\", "/"))
    if normalized.startswith("/") or ":" in normalized:
        raise LockError(f"{label} must be a repository-relative path")

    raw_parts = normalized.split("/")
    if any(part in {".", ".."} for part in raw_parts):
        raise LockError(f"{label} must not contain . or .. path segments")
    parts = [part for part in raw_parts if part]
    if not parts:
        raise LockError(f"{label} must name a repository path")

    for part in parts:
        if part.endswith((" ", ".")):
            raise LockError(f"{label} contains a Windows-ambiguous path segment")
        if part.casefold() == ".git":
            raise LockError(f"{label} must not target Git metadata")
        device_name = part.split(".", 1)[0].casefold()
        if device_name in WINDOWS_RESERVED_PATH_NAMES:
            raise LockError(f"{label} contains a Windows reserved path name")

    result = PurePosixPath(*parts).as_posix()
    if result in {"", "."}:
        raise LockError(f"{label} must name a repository path")
    return result


def path_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _is_descendant_or_equal(child: str, parent: str) -> bool:
    child_key = path_key(child)
    parent_key = path_key(parent)
    return child_key == parent_key or child_key.startswith(parent_key + "/")


def path_rules_intersect(
    first: dict[str, str], second: dict[str, str]
) -> bool:
    # A path may change between file and directory form while a cooperative
    # lock is live. Treat any ancestor/descendant relationship conservatively,
    # independent of whether either caller spelled its claim exact or prefix.
    return _is_descendant_or_equal(
        first["path"], second["path"]
    ) or _is_descendant_or_equal(second["path"], first["path"])


def normalize_path_rules(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise LockError("PATH_LOCK requires at least one exact or prefix path")
    normalized: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"kind", "path"}:
            raise LockError(f"paths[{index}] must contain only kind and path")
        if item["kind"] not in {"exact", "prefix"}:
            raise LockError(f"paths[{index}].kind must be exact or prefix")
        normalized.append(
            {
                "kind": item["kind"],
                "path": normalize_repo_path(item["path"], f"paths[{index}].path"),
            }
        )
    normalized.sort(key=lambda row: (path_key(row["path"]), row["kind"]))
    for index, rule in enumerate(normalized):
        for earlier in normalized[:index]:
            if path_rules_intersect(rule, earlier):
                raise LockError(
                    "one lock must not contain duplicate or internally overlapping paths"
                )
    return normalized


_READ_ONLY_GIT_COMMANDS = {
    ("rev-parse", "HEAD"),
    ("rev-parse", "--show-toplevel"),
    ("rev-parse", "--git-common-dir"),
    ("rev-parse", "--git-dir"),
    ("rev-parse", "--show-toplevel", "--git-common-dir"),
    ("worktree", "list", "--porcelain"),
}
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def _git_executable() -> str:
    allowed_directories: list[Path] = []
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        if not raw_entry:
            continue
        entry = Path(raw_entry)
        if not entry.is_absolute():
            continue
        allowed_directories.append(entry.resolve())
    if not allowed_directories:
        raise LockError("Git command unavailable")
    resolved = shutil.which(
        "git",
        path=os.pathsep.join(str(entry) for entry in allowed_directories),
    )
    if resolved is None:
        raise LockError("Git command unavailable")
    path = Path(resolved).resolve()
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.parent not in set(allowed_directories)
    ):
        raise LockError("Git command unavailable")
    return str(path)


def _git_observation_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    for variable in ("GCM_INTERACTIVE", "SSH_ASKPASS", "DISPLAY"):
        environment.pop(variable, None)
    environment.update({
        "GCM_INTERACTIVE": "Never", "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "GIT_TERMINAL_PROMPT": "0",
    })
    return environment


def _git_observation_spec(repo_root: Path, arguments: list[str]) -> tuple[list[str], dict[str, str], str]:
    """Build the exact sanitized local Git observation used by this runtime."""
    if tuple(arguments) not in _READ_ONLY_GIT_COMMANDS:
        raise LockError("Git observation command is outside the allowlist")
    executable = _git_executable()
    trusted_root = Path(repo_root).resolve()
    environment = _git_observation_environment()
    command = [
        executable, "-c", f"core.hooksPath={os.devnull}",
        "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-c", "credential.helper=", "-c", "core.askPass=",
        "-c", f"safe.directory={trusted_root.as_posix()}",
        "-C", str(trusted_root), *arguments,
    ]
    return command, environment, str(Path(executable).parent)


def _run_git(repo_root: Path, arguments: list[str]) -> str:
    command, environment, cwd = _git_observation_spec(repo_root, arguments)
    try:
        completed = subprocess.run(
            command, executable=command[0], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=60,
            env=environment, cwd=cwd,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LockError("Git command unavailable") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise LockError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout.strip()


def git_head(repo_root: Path) -> str:
    return require_git_oid(_run_git(repo_root, ["rev-parse", "HEAD"]), "HEAD")


def _git_repository_context(repo_root: Path, *, git_only: bool = False) -> tuple[Path, Path]:
    if git_only:
        _reject_identity_redirection(Path(os.path.abspath(repo_root)))
    resolved = Path(repo_root).resolve()
    observed = _run_git(resolved, ["rev-parse", "--show-toplevel", "--git-common-dir"]).splitlines()
    if len(observed) != 2:
        raise LockError("Git repository context observation has invalid shape")
    top = Path(observed[0]).resolve()
    if os.path.normcase(str(top)) != os.path.normcase(str(resolved)):
        raise LockError("repo_root must be the Git top-level directory")
    worktree_rows = _run_git(resolved, ["worktree", "list", "--porcelain"])
    worktree_count = sum(
        line.startswith("worktree ") for line in worktree_rows.splitlines()
    )
    if worktree_count < 1 or (worktree_count != 1 and not git_only):
        raise LockError(
            "this single-host runtime supports exactly one worktree per repository"
        )
    common_value = observed[1]
    common = Path(common_value)
    if not common.is_absolute():
        common = resolved / common
    if git_only:
        _reject_identity_redirection(common)
    return resolved, common.resolve()


def _reject_identity_redirection(path: Path) -> None:
    if any(_is_redirect(part) for part in (path, *path.parents)):
        raise LockError("Git-only worktree identity redirection is forbidden")


def _git_context(repo_root: Path) -> dict[str, str]:
    directory = Path(_run_git(repo_root, ["rev-parse", "--git-dir"]))
    if not directory.is_absolute():
        directory = repo_root / directory
    for path in (repo_root, repo_root / '.git', directory):
        _reject_identity_redirection(path)
    return {"repo_root": os.path.normcase(str(repo_root.resolve())),
            "git_dir": os.path.normcase(str(directory.resolve()))}


def _validate_git_context(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"repo_root", "git_dir"}:
        raise LockError("git_context must contain exactly repo_root and git_dir")
    for path in value.values():
        require_text(path, "git_context path")
        if not Path(path).is_absolute() or os.path.normcase(os.path.normpath(path)) != path:
            raise LockError("git_context paths must be canonical absolute paths")


def _is_redirect(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _validate_path_surface(repo_root: Path, rules: list[dict[str, str]]) -> None:
    for rule in rules:
        cursor = repo_root
        for segment in PurePosixPath(rule["path"]).parts:
            cursor = cursor / segment
            if os.path.lexists(cursor) and _is_redirect(cursor):
                raise LockError("path-lock symlink or reparse-point aliases are unsupported")


def _require_local_path(path: Path) -> None:
    text = str(path)
    if text.startswith(("\\\\", "//")):
        raise LockError("UNC runtime storage is unsupported")
    if os.name == "nt":
        import ctypes

        drive = path.drive
        if not drive:
            raise LockError("runtime storage must resolve to a local drive")
        if ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") == 4:
            raise LockError("remote-drive runtime storage is unsupported")


def _ensure_directory(path: Path, *, create: bool) -> bool:
    if not os.path.lexists(path):
        if not create:
            return False
        try:
            path.mkdir()
        except FileExistsError:
            pass
    if _is_redirect(path):
        raise LockError("runtime storage redirection is forbidden")
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise LockError("runtime storage component is not a directory")
    _require_local_path(path.resolve(strict=True))
    return True


_FAIRNESS_GATE_OFFSET = 1
# For the optional gate only these mean "another holder"; other gate errors
# drop the gate.  The mutex itself keeps retrying every OSError until the deadline.
_LOCK_CONTENTION_ERRNOS = frozenset(
    {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK, errno.EDEADLK}
)


def _poll_until(attempt: Callable[[], None], deadline: float, *, gate: bool = False) -> None:
    while True:
        try:
            attempt()
            return
        except OSError as error:
            if gate and error.errno not in _LOCK_CONTENTION_ERRNOS:
                raise LockUnavailable(f"coordination lock is unavailable: {error}") from error
            if time.monotonic() >= deadline:
                raise LockError("coordination lock acquisition timed out") from error
            time.sleep(0.025)


def _fairness_gate(handle: Any, lock_path: Path) -> tuple[Callable[[], None], Callable[[], None], Callable[[], None]] | None:
    """Return take/drop/close for the waiter gate, or None when it cannot be opened.

    With an available gate, a waiter holds it while polling the mutex, so a
    caller that also takes the gate cannot retake the mutex before that waiter
    (two contenders; three or more still race for the gate); callers that fall
    back or ignore the gate can.  The gate only orders waiters:
    mutual exclusion is the byte-0 (Windows) or file flock (POSIX) mutex alone,
    so runtimes that ignore the gate stay excluded and running without it is safe.
    """
    if os.name == "nt":
        import msvcrt

        def take() -> None:
            handle.seek(_FAIRNESS_GATE_OFFSET)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

        def drop() -> None:
            handle.seek(_FAIRNESS_GATE_OFFSET)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

        return take, drop, lambda: None
    import fcntl

    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    try:
        gate = os.open(lock_path.parent, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(gate)
        if not stat.S_ISDIR(metadata.st_mode) or not os.path.samestat(
            metadata, os.lstat(lock_path.parent)
        ):
            raise OSError(errno.ENOTDIR, "waiter gate directory identity changed")
    except OSError:
        try:
            os.close(gate)
        except OSError:
            pass
        return None
    return (
        lambda: fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB),
        lambda: fcntl.flock(gate, fcntl.LOCK_UN),
        lambda: os.close(gate),
    )


def _acquire_with_gate(take_mutex: Callable[[], None], handle: Any, lock_path: Path, deadline: float) -> None:
    gate = _fairness_gate(handle, lock_path)
    if gate is None:
        _poll_until(take_mutex, deadline)
        return
    take_gate, drop_gate, close_gate = gate
    try:
        try:
            _poll_until(take_gate, deadline, gate=True)
        except LockUnavailable:
            _poll_until(take_mutex, deadline)
            return
        try:
            _poll_until(take_mutex, deadline)
        finally:
            try:
                drop_gate()
            except OSError:
                pass
    finally:
        try:
            close_gate()
        except OSError:
            pass


@contextmanager
def _interprocess_lock(lock_path: Path, timeout_seconds: float) -> Iterator[None]:
    if not os.path.lexists(lock_path) or _is_redirect(lock_path):
        raise LockError("coordination lock file is absent or redirected")
    if not stat.S_ISREG(os.lstat(lock_path).st_mode):
        raise LockError("coordination lock path is not a regular file")
    with lock_path.open("r+b") as handle:
        deadline = time.monotonic() + timeout_seconds
        handle.seek(0, os.SEEK_END)
        while handle.tell() == 0:
            if time.monotonic() >= deadline:
                raise LockError("coordination lock file is incomplete")
            time.sleep(0.025)
            handle.seek(0, os.SEEK_END)

        held = False

        def take_mutex() -> None:
            nonlocal held
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = True

        try:
            _acquire_with_gate(take_mutex, handle, lock_path, deadline)
            locked_metadata = os.fstat(handle.fileno())
            path_metadata = os.lstat(lock_path)
            if _is_redirect(lock_path) or not os.path.samestat(
                locked_metadata, path_metadata
            ):
                raise LockError("coordination lock identity changed")
            yield
        finally:
            if held:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _atomic_replace(source: Path, destination: Path) -> None:
    """Retry only transient Windows sharing denials; retain atomic replacement."""

    for attempt in range(len(WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS) + 1):
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            if os.name != "nt" or attempt == len(WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS):
                raise
            time.sleep(WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS[attempt])


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _atomic_replace(temporary, path)
    except OSError as error:
        raise LockError(f"runtime state cannot be written atomically: {error}") from error
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def _empty_state() -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "coordination_scope": COORDINATION_SCOPE,
        "locks": [],
    }


def _validate_record(record: Any, label: str) -> dict[str, Any]:
    required = {
        "schema_version",
        "object_kind",
        "lock_id",
        "lock_kind",
        "task",
        "owner",
        "base_head",
        "paths",
        "acquired_at",
        "expires_at",
        "ttl_seconds",
        "nonce",
    }
    if not isinstance(record, dict) or set(record) not in (required, required | {"git_context"}):
        raise LockError(f"{label} must contain exactly the lock-record fields")
    if record["schema_version"] != STATE_SCHEMA_VERSION:
        raise LockError(f"{label}.schema_version must be {STATE_SCHEMA_VERSION}")
    if record["object_kind"] != "DYNAMIC_COORDINATION_LOCK":
        raise LockError(f"{label}.object_kind is invalid")
    require_text(record["lock_id"], f"{label}.lock_id")
    kind = canonical_lock_kind(record["lock_kind"])
    if kind != record["lock_kind"]:
        raise LockError(f"{label}.lock_kind must use the current canonical name")
    if "git_context" in record:
        if kind != "GIT_MUTATION_LOCK":
            raise LockError("git_context is only valid for GIT_MUTATION_LOCK")
        _validate_git_context(record["git_context"])
    require_text(record["task"], f"{label}.task")
    require_text(record["owner"], f"{label}.owner")
    require_git_oid(record["base_head"], f"{label}.base_head")
    require_text(record["nonce"], f"{label}.nonce")
    require_ttl(
        record["ttl_seconds"],
        maximum=(
            MAX_GIT_MUTATION_TTL_SECONDS
            if kind == "GIT_MUTATION_LOCK"
            else MAX_TTL_SECONDS
        ),
    )
    acquired = parse_utc(record["acquired_at"], f"{label}.acquired_at")
    expires = parse_utc(record["expires_at"], f"{label}.expires_at")
    if expires <= acquired:
        raise LockError(f"{label}.expires_at must be after acquired_at")
    if kind == "PATH_LOCK":
        normalized = normalize_path_rules(record["paths"])
        if normalized != record["paths"]:
            raise LockError(f"{label}.paths must be canonical and sorted")
    elif record["paths"] != []:
        raise LockError(f"{label}.paths must be empty for GIT_MUTATION_LOCK")
    return record


def _validate_state(state: Any, now: datetime) -> dict[str, Any]:
    if not isinstance(state, dict) or set(state) != {
        "schema_version",
        "coordination_scope",
        "locks",
    }:
        raise LockError("runtime state must contain exactly schema, scope, and locks")
    if state["schema_version"] != STATE_SCHEMA_VERSION:
        raise LockError(f"runtime state schema_version must be {STATE_SCHEMA_VERSION}")
    if state["coordination_scope"] != COORDINATION_SCOPE:
        raise LockError("runtime coordination_scope is invalid")
    if not isinstance(state["locks"], list):
        raise LockError("runtime locks must be a list")
    for index, record in enumerate(state["locks"]):
        _validate_record(record, f"locks[{index}]")
    identifiers = [record["lock_id"] for record in state["locks"]]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise LockError("runtime lock IDs must be sorted and unique")

    active = [
        record
        for record in state["locks"]
        if parse_utc(record["expires_at"], "expires_at") > now
    ]
    git_locks = [record for record in active if record["lock_kind"] == "GIT_MUTATION_LOCK"]
    if len(git_locks) > 1:
        raise LockError("runtime state contains multiple active Git mutation locks")
    path_locks = [record for record in active if record["lock_kind"] == "PATH_LOCK"]
    if git_locks and path_locks:
        raise LockError(
            "runtime state contains concurrent path and Git mutation locks"
        )
    for index, record in enumerate(path_locks):
        for other in path_locks[:index]:
            if _rules_intersect(record["paths"], other["paths"]):
                raise LockError("runtime state contains overlapping active path locks")
    return state


def _legacy_state_to_current(
    value: dict[str, Any], now: datetime
) -> dict[str, Any]:
    leases = value.get("leases")
    if not isinstance(leases, list):
        raise LockError("legacy runtime state has no readable leases list")
    records: list[dict[str, Any]] = []
    for index, lease in enumerate(leases):
        if not isinstance(lease, dict):
            raise LockError(f"legacy leases[{index}] must be an object")
        expires_at = parse_utc(
            lease.get("expires_at"), f"legacy leases[{index}].expires_at"
        )
        if expires_at <= now:
            continue
        if lease.get("state") != "ACTIVE":
            raise LockError(
                f"legacy unexpired lease {index} has an ambiguous state"
            )
        legacy_class = lease.get("lease_class")
        if legacy_class == "GIT_PUBLICATION_LEASE":
            if lease.get("write_paths") not in (None, []):
                raise LockError(
                    "legacy unexpired Git publication lease also claims paths; "
                    "wait for expiry or release it with the legacy runtime"
                )
            kind = "GIT_MUTATION_LOCK"
            paths: list[dict[str, str]] = []
        elif legacy_class in {
            "PROJECT_PATH_LEASE",
            *RETIRED_AUTHORITY_LEASE_CLASSES,
        }:
            kind = "PATH_LOCK"
            try:
                paths = normalize_path_rules(lease.get("write_paths"))
            except LockError as error:
                raise LockError(
                    f"legacy active lease {index} cannot be migrated safely: {error}"
                ) from error
        else:
            raise LockError(
                f"legacy unexpired lease {index} has an unsupported class"
            )
        remaining_seconds = max(1, int((expires_at - now).total_seconds()))
        maximum = (
            MAX_GIT_MUTATION_TTL_SECONDS
            if kind == "GIT_MUTATION_LOCK"
            else MAX_TTL_SECONDS
        )
        migrated_ttl = min(remaining_seconds, maximum)
        record = {
            "schema_version": STATE_SCHEMA_VERSION,
            "object_kind": "DYNAMIC_COORDINATION_LOCK",
            "lock_id": require_text(lease.get("lease_id"), f"legacy leases[{index}].lease_id"),
            "lock_kind": kind,
            "task": require_text(
                lease.get("task_package_id"),
                f"legacy leases[{index}].task_package_id",
            ),
            "owner": require_text(lease.get("owner"), f"legacy leases[{index}].owner"),
            "base_head": require_git_oid(
                lease.get("base_head"), f"legacy leases[{index}].base_head"
            ),
            "paths": paths,
            "acquired_at": format_utc(now),
            "expires_at": format_utc(now + timedelta(seconds=migrated_ttl)),
            "ttl_seconds": migrated_ttl,
            "nonce": require_text(lease.get("nonce"), f"legacy leases[{index}].nonce"),
        }
        _validate_record(record, f"legacy leases[{index}]")
        records.append(record)
    records.sort(key=lambda record: record["lock_id"])
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "coordination_scope": COORDINATION_SCOPE,
        "locks": records,
    }


def _rules_intersect(
    first: list[dict[str, str]], second: list[dict[str, str]]
) -> bool:
    return any(
        path_rules_intersect(left, right)
        for left in first
        for right in second
    )


class LockCoordinator:
    """Atomic, host-local concurrency coordination with no authority semantics."""

    def __init__(
        self,
        repo_root: Path,
        control_plane: Path | None = None,
        *,
        now_fn: Callable[[], datetime] = utc_now,
        lock_timeout_seconds: float = 5.0,
        git_only: bool = False,
    ) -> None:
        if not isinstance(git_only, bool):
            raise LockError("git_only must be boolean")
        self.git_only = git_only
        self.repo_root, self.git_common_dir = _git_repository_context(Path(repo_root), git_only=git_only)
        self.git_context = _git_context(self.repo_root) if git_only else None
        # The v1 directory name is retained so old and new runtimes serialize on
        # the same OS lock during the one-way state migration.
        self.runtime_dir = self.git_common_dir / "toplayer-runtime" / "leases-v1"
        self.state_path = self.runtime_dir / "state.json"
        self.lock_path = self.runtime_dir / "state.lock"
        self.now_fn = now_fn
        self.lock_timeout_seconds = lock_timeout_seconds
        self.control_plane = control_plane  # accepted but intentionally unused

    def _revalidate_context(self) -> None:
        current = _git_repository_context(self.repo_root, git_only=self.git_only)
        if current != (self.repo_root, self.git_common_dir):
            raise LockError("repository context changed")
        if self.git_only and _git_context(self.repo_root) != self.git_context:
            raise LockError("Git-only worktree identity changed")

    def _validate_owned_context(self, record: dict[str, Any]) -> None:
        if self.git_only:
            if record["lock_kind"] != "GIT_MUTATION_LOCK" or record.get("git_context") != self.git_context:
                raise LockError("Git-only lock requires its exact acquired worktree context")
        elif "git_context" in record:
            raise LockError("Git-only lock requires explicit git_only mode")

    def _storage_ready(self, *, create: bool) -> bool:
        _require_local_path(self.git_common_dir)
        parent = self.git_common_dir / "toplayer-runtime"
        if not _ensure_directory(parent, create=create):
            return False
        if not _ensure_directory(self.runtime_dir, create=create):
            return False
        if not os.path.lexists(self.lock_path):
            if os.path.lexists(self.state_path):
                raise LockError("runtime state exists but its coordination lock file is absent")
            if not create:
                return False
            try:
                with self.lock_path.open("xb") as handle:
                    handle.write(b"0")
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError:
                pass
        if _is_redirect(self.lock_path) or not stat.S_ISREG(
            os.lstat(self.lock_path).st_mode
        ):
            raise LockError("coordination lock path is unsafe")
        return True

    def _read_state(self, now: datetime) -> tuple[dict[str, Any], bool]:
        if not self.state_path.exists():
            return _empty_state(), False
        if _is_redirect(self.state_path):
            raise LockError("runtime state redirection is forbidden")
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LockError(f"runtime state is unreadable: {error}") from error
        if not isinstance(value, dict):
            raise LockError("runtime state must be a JSON object")
        legacy = value.get("schema_version") == 1
        if legacy:
            value = _legacy_state_to_current(value, now)
        return _validate_state(value, now), legacy

    def _write_state(self, state: dict[str, Any], now: datetime) -> None:
        state["locks"].sort(key=lambda record: record["lock_id"])
        _validate_state(state, now)
        _atomic_write_json(self.state_path, state)

    def status(self) -> dict[str, Any]:
        if not self._storage_ready(create=False) or not self.state_path.exists():
            self._revalidate_context()
            return {
                "status": "OK",
                "coordination_scope": COORDINATION_SCOPE,
                "runtime_state": "ABSENT",
                "legacy_runtime_detected": False,
                "active_locks": [],
                "expired_locks": [],
            }
        with _interprocess_lock(self.lock_path, self.lock_timeout_seconds):
            self._revalidate_context()
            now = self.now_fn().astimezone(timezone.utc)
            state, legacy = self._read_state(now)
            now = self.now_fn().astimezone(timezone.utc)
        active: list[dict[str, Any]] = []
        expired: list[dict[str, Any]] = []
        for record in state["locks"]:
            target = (
                active
                if parse_utc(record["expires_at"], "expires_at") > now
                else expired
            )
            target.append(record)
        return {
            "status": "OK",
            "coordination_scope": COORDINATION_SCOPE,
            "runtime_state": "PRESENT",
            "legacy_runtime_detected": legacy,
            "active_locks": active,
            "expired_locks": expired,
        }

    def acquire(
        self,
        *,
        lock_kind: str,
        task: str,
        owner: str,
        ttl_seconds: int,
        paths: list[dict[str, str]] | None = None,
        nonce: str | None = None,
        lock_id: str | None = None,
        base_head: str | None = None,
    ) -> dict[str, Any]:
        kind = canonical_lock_kind(lock_kind)
        if self.git_only and kind != "GIT_MUTATION_LOCK":
            raise LockError("Git-only mode does not support PATH_LOCK")
        self._revalidate_context()
        task = require_text(task, "task")
        owner = require_text(owner, "owner")
        ttl = require_ttl(
            ttl_seconds,
            maximum=(
                MAX_GIT_MUTATION_TTL_SECONDS
                if kind == "GIT_MUTATION_LOCK"
                else MAX_TTL_SECONDS
            ),
        )
        nonce = require_text(nonce or uuid.uuid4().hex, "nonce")
        lock_id = require_text(lock_id or f"LOCK-{uuid.uuid4().hex}", "lock_id")
        normalized_paths = normalize_path_rules(paths) if kind == "PATH_LOCK" else []
        if kind == "GIT_MUTATION_LOCK" and paths not in (None, [], ()):
            raise LockError("GIT_MUTATION_LOCK does not accept paths")
        if kind == "PATH_LOCK":
            _validate_path_surface(self.repo_root, normalized_paths)

        current_head = git_head(self.repo_root)
        if base_head is not None and require_git_oid(base_head) != current_head:
            raise LockError("base_head assertion does not match current HEAD")
        self._storage_ready(create=True)
        with _interprocess_lock(self.lock_path, self.lock_timeout_seconds):
            self._revalidate_context()
            if self.git_only:
                current_head = git_head(self.repo_root)
                if base_head is not None and require_git_oid(base_head) != current_head:
                    raise LockError("base_head assertion does not match current HEAD")
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            state, legacy = self._read_state(now)
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            expires = now + timedelta(seconds=ttl)
            expired_ids = [
                record["lock_id"]
                for record in state["locks"]
                if parse_utc(record["expires_at"], "expires_at") <= now
            ]
            state["locks"] = [
                record
                for record in state["locks"]
                if parse_utc(record["expires_at"], "expires_at") > now
            ]
            if any(record["lock_id"] == lock_id for record in state["locks"]):
                raise LockError(f"active lock_id already exists: {lock_id}")
            if kind == "GIT_MUTATION_LOCK":
                conflicts = [
                    record["lock_id"]
                    for record in state["locks"]
                ]
            else:
                conflicts = [
                    record["lock_id"]
                    for record in state["locks"]
                    if record["lock_kind"] == "GIT_MUTATION_LOCK"
                    or (
                        record["lock_kind"] == "PATH_LOCK"
                        and _rules_intersect(normalized_paths, record["paths"])
                    )
                ]
            if conflicts:
                raise LockConflict(
                    "lock conflict requires wait, coordination, or handoff: "
                    + ", ".join(sorted(conflicts))
                )
            record = {
                "schema_version": STATE_SCHEMA_VERSION,
                "object_kind": "DYNAMIC_COORDINATION_LOCK",
                "lock_id": lock_id,
                "lock_kind": kind,
                "task": task,
                "owner": owner,
                "base_head": current_head,
                "paths": normalized_paths,
                "acquired_at": format_utc(now),
                "expires_at": format_utc(expires),
                "ttl_seconds": ttl,
                "nonce": nonce,
            }
            if self.git_only:
                record["git_context"] = dict(self.git_context)
            state["locks"].append(record)
            self._write_state(state, now)
        return {
            "status": "ACQUIRED",
            "lock": record,
            "stale_locks_recovered": sorted(expired_ids),
            "legacy_runtime_migrated": legacy,
            "legacy_alias_used": lock_kind if lock_kind != kind else None,
        }

    def renew(
        self,
        *,
        lock_id: str,
        owner: str,
        nonce: str,
        ttl_seconds: int,
        new_nonce: str | None = None,
    ) -> dict[str, Any]:
        lock_id = require_text(lock_id, "lock_id")
        owner = require_text(owner, "owner")
        nonce = require_text(nonce, "nonce")
        new_nonce = require_text(new_nonce or uuid.uuid4().hex, "new_nonce")

        if not self._storage_ready(create=False) or not self.state_path.exists():
            raise LockError(f"unknown lock_id: {lock_id}")
        with _interprocess_lock(self.lock_path, self.lock_timeout_seconds):
            self._revalidate_context()
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            state, legacy = self._read_state(now)
            target = next(
                (record for record in state["locks"] if record["lock_id"] == lock_id),
                None,
            )
            if target is None:
                raise LockError(f"unknown lock_id: {lock_id}")
            if target["owner"] != owner or target["nonce"] != nonce:
                raise LockError("lock owner or nonce mismatch")
            self._validate_owned_context(target)
            ttl = require_ttl(
                ttl_seconds,
                maximum=(
                    MAX_GIT_MUTATION_TTL_SECONDS
                    if target["lock_kind"] == "GIT_MUTATION_LOCK"
                    else MAX_TTL_SECONDS
                ),
            )
            if target["lock_kind"] == "PATH_LOCK":
                _validate_path_surface(self.repo_root, target["paths"])
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            expired = parse_utc(target["expires_at"], "expires_at") <= now
            stale_ids = sorted(
                record["lock_id"]
                for record in state["locks"]
                if record is not target
                and parse_utc(record["expires_at"], "expires_at") <= now
            )
            state["locks"] = [
                record
                for record in state["locks"]
                if record is target
                or parse_utc(record["expires_at"], "expires_at") > now
            ]
            if expired:
                if target["lock_kind"] == "GIT_MUTATION_LOCK":
                    conflict = any(
                        record is not target
                        for record in state["locks"]
                    )
                else:
                    conflict = any(
                        record is not target
                        and (
                            record["lock_kind"] == "GIT_MUTATION_LOCK"
                            or (
                                record["lock_kind"] == "PATH_LOCK"
                                and _rules_intersect(target["paths"], record["paths"])
                            )
                        )
                        for record in state["locks"]
                    )
                if conflict:
                    raise LockConflict(
                        "expired lock recovery conflicts with a current lock"
                    )
                target["base_head"] = git_head(self.repo_root)
                now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            target["acquired_at"] = format_utc(now)
            target["expires_at"] = format_utc(now + timedelta(seconds=ttl))
            target["ttl_seconds"] = ttl
            target["nonce"] = new_nonce
            self._write_state(state, now)
        return {
            "status": "RECOVERED" if expired else "RENEWED",
            "lock": target,
            "legacy_runtime_migrated": legacy,
            "stale_locks_recovered": stale_ids,
        }

    def renew_active(
        self,
        *,
        lock_id: str,
        owner: str,
        nonce: str,
        ttl_seconds: int,
        new_nonce: str | None = None,
    ) -> dict[str, Any]:
        """Strictly renew one currently active lock without stale recovery.

        This operation deliberately has a narrower contract than :meth:`renew`.
        It never prunes other records, never changes an expired record, and never
        uses an expired claim as the basis for a new exclusive interval.  Callers
        that need legacy stale-lock recovery must continue to use ``renew``.
        """

        # Fresh topology and identity are checked under the state mutex below.
        # Repeating the same Git queries before it exhausts short heartbeats.
        lock_id = require_text(lock_id, "lock_id")
        owner = require_text(owner, "owner")
        nonce = require_text(nonce, "nonce")
        new_nonce = require_text(new_nonce or uuid.uuid4().hex, "new_nonce")

        if not self._storage_ready(create=False) or not self.state_path.exists():
            raise LockError(f"unknown lock_id: {lock_id}")
        with _interprocess_lock(self.lock_path, self.lock_timeout_seconds):
            self._revalidate_context()
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            state, legacy = self._read_state(now)
            target = next(
                (record for record in state["locks"] if record["lock_id"] == lock_id),
                None,
            )
            if target is None:
                raise LockError(f"unknown lock_id: {lock_id}")
            if target["owner"] != owner or target["nonce"] != nonce:
                raise LockError("lock owner or nonce mismatch")
            self._validate_owned_context(target)
            ttl = require_ttl(
                ttl_seconds,
                maximum=(
                    MAX_GIT_MUTATION_TTL_SECONDS
                    if target["lock_kind"] == "GIT_MUTATION_LOCK"
                    else MAX_TTL_SECONDS
                ),
            )
            if target["lock_kind"] == "PATH_LOCK":
                _validate_path_surface(self.repo_root, target["paths"])
            # Lock acquisition, context validation, state I/O and path checks
            # can consume the remainder of the lease. Decide with fresh time.
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            if parse_utc(target["expires_at"], "expires_at") <= now:
                # No state mutation is permitted on this path.  In particular,
                # do not turn an expired record into a recovered claim.
                raise LockError("strict renewal requires an unexpired active lock")
            target["acquired_at"] = format_utc(now)
            target["expires_at"] = format_utc(now + timedelta(seconds=ttl))
            target["ttl_seconds"] = ttl
            target["nonce"] = new_nonce
            self._write_state(state, now)
        return {
            "status": "RENEWED",
            "lock": target,
            "legacy_runtime_migrated": legacy,
            "strict": True,
        }

    def release(
        self,
        *,
        lock_id: str,
        owner: str,
        nonce: str,
    ) -> dict[str, Any]:
        lock_id = require_text(lock_id, "lock_id")
        owner = require_text(owner, "owner")
        nonce = require_text(nonce, "nonce")

        if not self._storage_ready(create=False) or not self.state_path.exists():
            raise LockError(f"unknown lock_id: {lock_id}")
        with _interprocess_lock(self.lock_path, self.lock_timeout_seconds):
            self._revalidate_context()
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            state, legacy = self._read_state(now)
            target = next(
                (record for record in state["locks"] if record["lock_id"] == lock_id),
                None,
            )
            if target is None:
                raise LockError(f"unknown lock_id: {lock_id}")
            if target["owner"] != owner or target["nonce"] != nonce:
                raise LockError("lock owner or nonce mismatch")
            self._validate_owned_context(target)
            now = self.now_fn().astimezone(timezone.utc).replace(microsecond=0)
            observed_state = (
                "EXPIRED"
                if parse_utc(target["expires_at"], "expires_at") <= now
                else "ACTIVE"
            )
            state["locks"] = [
                record for record in state["locks"] if record is not target
            ]
            self._write_state(state, now)
        return {
            "status": "RELEASED",
            "lock_id": lock_id,
            "observed_state": observed_state,
            "legacy_runtime_migrated": legacy,
        }


# Import compatibility only. The implementation and returned records use lock
# terminology and contain no grant, capability, receipt, or publication gate.
LeaseCoordinator = LockCoordinator
